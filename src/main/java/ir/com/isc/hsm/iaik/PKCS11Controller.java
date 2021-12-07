package ir.com.isc.hsm.iaik;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Formatter;

public class PKCS11Controller {
  private static final Logger logger = LoggerFactory.getLogger("PKCS11Controller");
  private Module p11;
  private Token token;
  private Session session;
  private Object[] createdObjects;
  private int currentObjectIndex;
  private int indexOfGeneratedAESKey;
  private int indexOfGeneratedRSAPublicKey;
  private int indexOfGeneratedRSAPrivateKey;
  private static long slotID;

  private static final int MAX_NUMBER_OF_SEARCHED_OBJECT = 100;
  private static final int MAX_NUMBER_OF_OBJECT_CREATED_IN_CURRENT_SESSION = 4;

  public PKCS11Controller() {
    // Initialize variables
    p11 = null;
    token = null;
    session = null;
    slotID = -1;
    createdObjects = new Object[MAX_NUMBER_OF_OBJECT_CREATED_IN_CURRENT_SESSION];
    currentObjectIndex = 0;
    indexOfGeneratedAESKey = -1;
    indexOfGeneratedRSAPublicKey = -1;
    indexOfGeneratedRSAPrivateKey = -1;
  }

  public String getModulePathBaseOnOS() {
    String operationSystem = System.getProperty("os.name").toLowerCase();
    String result = "";
    if (operationSystem.contains("nix")
        || operationSystem.contains("nux")
        || operationSystem.contains("aix")
        || operationSystem.contains("centos")) {
      result = "/hsm/iwinHSM/confs/libqashqai.so";
    } else if (operationSystem.contains("win")) {
      result = "c:/hsm/iwinHSM/confs/DLLQashqai.dll";
    } else {
      logger.error("Cannot detect operating system to load appropriate module!");
    }

    return result;
  }

  public boolean initializePKCS11Library(String pkcs11ModulePath) {
    try {
      p11 = Module.getInstance(pkcs11ModulePath);
      p11.initialize(new DefaultInitializeArgs());
    } catch (Exception e) {
      logger.error(e.toString());
      return false;
    }
    return true;
  }

  public boolean getFirstAvailableSlotID() {
    Slot[] slotsWithToken;
    try {
      slotsWithToken = p11.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
      if (slotsWithToken.length <= 0) {
        logger.error("There is no slot/partition!");
        return false;
      } else {
        slotID = slotsWithToken[0].getSlotID();
        token = slotsWithToken[0].getToken();
        if (token == null) {
          logger.error("Cannot get token from the first slot!");
          return false;
        }
      }
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }
    return true;
  }

  public long getSlotID() {
    return slotID;
  }

  public boolean showTokenInfo() {
    TokenInfo tmpInfo;
    try {
      tmpInfo = token.getTokenInfo();
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }

    logger.info(" CK_TOKEN_INFO for SlotID {} :", slotID);
    logger.info("label:           {}", tmpInfo.getLabel());
    logger.info("manufacturerID:  {}", tmpInfo.getManufacturerID());
    logger.info("model:           {}", tmpInfo.getModel());
    logger.info("serialNumber:    {}", tmpInfo.getSerialNumber());
    logger.info("ulMaxPinLen:     {}", tmpInfo.getMaxPinLen());
    logger.info("ulMinPinLen:     {}", tmpInfo.getMinPinLen());
    logger.info("hardwareVersion: {}", tmpInfo.getHardwareVersion());
    logger.info("firmwareVersion: {}", tmpInfo.getFirmwareVersion());

    return true;
  }

  public boolean openSession() {
    try {
      session =
          token.openSession(
              Token.SessionType.SERIAL_SESSION,
              Token.SessionReadWriteBehavior.RW_SESSION,
              null,
              null);
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }
    return true;
  }

  public boolean login(String userPin) {
    try {
      session.login(Session.UserType.USER, userPin.toCharArray());
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }

    return true;
  }

  public boolean generateAESKey(String keyLabel) {
    AESSecretKey symKeyTemplate;
    Object symKey;
    try {
      symKeyTemplate = new AESSecretKey();

      symKeyTemplate.putAttribute(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY);
      symKeyTemplate.putAttribute(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_AES);
      symKeyTemplate.putAttribute(PKCS11Constants.CKA_VALUE_LEN, new Long(32));
      symKeyTemplate.putAttribute(PKCS11Constants.CKA_LABEL, keyLabel.toCharArray());
      symKeyTemplate.putAttribute(PKCS11Constants.CKA_TOKEN, true);
      symKeyTemplate.putAttribute(PKCS11Constants.CKA_ENCRYPT, true);
      symKeyTemplate.putAttribute(PKCS11Constants.CKA_DECRYPT, true);

      Mechanism keyGenerationMechanism = new Mechanism(PKCS11Constants.CKM_AES_KEY_GEN);
      symKey = session.generateKey(keyGenerationMechanism, symKeyTemplate);
      indexOfGeneratedAESKey = currentObjectIndex;
      createdObjects[currentObjectIndex++] = symKey;
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }

    logger.info("An AES key was generated successfully.");
    logger.info("Key handle {} was assigned to the generated AES key.", symKey.getObjectHandle());
    return true;
  }

  public boolean generateRSAKeyPair(String publicKeyLabel, String privateKeyLabel) {
    long start = System.currentTimeMillis();
    RSAPublicKey publicKeyTemplate;
    RSAPrivateKey privateKeyTemplate;
    KeyPair keyPair;
    try {
      // Public key temp
      publicKeyTemplate = new RSAPublicKey();
      publicKeyTemplate.putAttribute(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PUBLIC_KEY);
      publicKeyTemplate.putAttribute(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_RSA);
      publicKeyTemplate.putAttribute(PKCS11Constants.CKA_TOKEN, true);
      publicKeyTemplate.putAttribute(PKCS11Constants.CKA_LABEL, publicKeyLabel.toCharArray());
      publicKeyTemplate.putAttribute(PKCS11Constants.CKA_ENCRYPT, true);
      publicKeyTemplate.putAttribute(PKCS11Constants.CKA_VERIFY, true);
      publicKeyTemplate.putAttribute(PKCS11Constants.CKA_WRAP, true);
      publicKeyTemplate.putAttribute(PKCS11Constants.CKA_MODULUS_BITS, new Long(2048));
      byte[] publicExponent = new byte[] {(byte) 0x01, (byte) 0x00, (byte) 0x01};
      publicKeyTemplate.putAttribute(PKCS11Constants.CKA_PUBLIC_EXPONENT, publicExponent);

      // Private key template
      privateKeyTemplate = new RSAPrivateKey();
      privateKeyTemplate.putAttribute(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PRIVATE_KEY);
      privateKeyTemplate.putAttribute(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_RSA);
      privateKeyTemplate.putAttribute(PKCS11Constants.CKA_TOKEN, true);
      privateKeyTemplate.putAttribute(PKCS11Constants.CKA_LABEL, privateKeyLabel.toCharArray());
      privateKeyTemplate.putAttribute(PKCS11Constants.CKA_PRIVATE, true);
      privateKeyTemplate.putAttribute(PKCS11Constants.CKA_DECRYPT, true);
      privateKeyTemplate.putAttribute(PKCS11Constants.CKA_SIGN, true);
      privateKeyTemplate.putAttribute(PKCS11Constants.CKA_SENSITIVE, true);

      Mechanism keypairGenerationMechanism =
          new Mechanism(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
      keyPair =
          session.generateKeyPair(
              keypairGenerationMechanism, publicKeyTemplate, privateKeyTemplate);
      indexOfGeneratedRSAPublicKey = currentObjectIndex;
      createdObjects[currentObjectIndex++] = keyPair.getPublicKey();
      indexOfGeneratedRSAPrivateKey = currentObjectIndex;
      createdObjects[currentObjectIndex++] = keyPair.getPrivateKey();
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }
    logger.info("An RSA key pair was generated successfully.");
    logger.info(
        "Key handles {} and {} were assigned to public and private keys respectively, time {}.",
        keyPair.getPublicKey().getObjectHandle(),
        keyPair.getPrivateKey().getObjectHandle(),
        System.currentTimeMillis() - start);
    return true;
  }

  public boolean createObject(String keyLabel, byte[] keyValue) {
    AESSecretKey secretKeyTemplate;
    Object secretKey;
    try {
      // Constructing template
      secretKeyTemplate = new AESSecretKey();
      secretKeyTemplate.putAttribute(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY);
      secretKeyTemplate.putAttribute(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_AES);
      secretKeyTemplate.putAttribute(PKCS11Constants.CKA_TOKEN, true);
      secretKeyTemplate.putAttribute(PKCS11Constants.CKA_LABEL, keyLabel.toCharArray());
      secretKeyTemplate.putAttribute(PKCS11Constants.CKA_ENCRYPT, true);
      secretKeyTemplate.putAttribute(PKCS11Constants.CKA_DECRYPT, true);
      secretKeyTemplate.putAttribute(PKCS11Constants.CKA_VALUE, keyValue);

      secretKey = session.createObject(secretKeyTemplate);
      createdObjects[currentObjectIndex++] = secretKey;
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }

    logger.info("An AES Key was imported successfully.");
    logger.info("Key handle {} was assigned to the imported AES key.", secretKey.getObjectHandle());
    return true;
  }

  public boolean findObjectByLabel(String label) {
    Storage searchTemplate = new Storage();
    searchTemplate.getLabel().setCharArrayValue(label.toCharArray());

    try {
      session.findObjectsInit(searchTemplate);
    } catch (Exception e) {
      logger.error("Cannot initialize find object!", e);
      return false;
    }

    int numberOfObjects = -1;
    try {
      Object[] objects = session.findObjects(MAX_NUMBER_OF_SEARCHED_OBJECT);
      numberOfObjects = objects.length;
    } catch (Exception e) {
      logger.error("Cannot accomplish finding process!", e);
      return false;
    } finally {
      try {
        session.findObjectsFinal();
      } catch (Exception ex) {
        logger.error("Cannot finalize the find object operation!", ex);
      }
    }

    if (numberOfObjects > 0) {
      logger.info("Found {} object(s) on token with label {}.", numberOfObjects, label);
    } else logger.info("There is no object with label {} on the token.", label);

    return true;
  }

  public boolean getAttributesTest() {
    logger.info("Getting attributes from public key...");
    if (indexOfGeneratedRSAPublicKey < 0) {
      logger.error("Cannot retrieve the generated RSA public key!");
      return false;
    }

    Object object = createdObjects[indexOfGeneratedRSAPublicKey];

    try {
      // Get attributes
      logger.info("Public exponent: {}", object.getAttribute(PKCS11Constants.CKA_PUBLIC_EXPONENT));
      logger.info("Modulus: {}", object.getAttribute(PKCS11Constants.CKA_MODULUS));
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }
    return true;
  }

  public boolean encryptDecryptTest() {
    byte[] iv = {
      (byte) 0xAA,
      (byte) 0xBB,
      (byte) 0xCC,
      (byte) 0xDD,
      (byte) 0xEE,
      (byte) 0xFF,
      (byte) 0x00,
      (byte) 0x11,
      (byte) 0xAA,
      (byte) 0xBB,
      (byte) 0xCC,
      (byte) 0xDD,
      (byte) 0xEE,
      (byte) 0xFF,
      (byte) 0x00,
      (byte) 0x11
    };
    int testDataLen = 100;
    logger.info("Encrypting a random message using the generated AES key...");

    try {
      byte[] testData = session.generateRandom(testDataLen);
      logger.info("Generated random message: {}", byteArrayToHexString(testData));

      // Encrypt
      logger.info("Encrypting the message...");
      Mechanism encryptDecryptMechanism = new Mechanism(PKCS11Constants.CKM_AES_CBC_PAD);
      encryptDecryptMechanism.setParameters(new InitializationVectorParameters(iv));
      session.encryptInit(encryptDecryptMechanism, (Key) createdObjects[indexOfGeneratedAESKey]);
      byte[] encData = session.encrypt(testData);
      logger.info("Data was encrypted successfully");
      logger.info("Encrypted message: {}", byteArrayToHexString(encData));

      // Decrypt
      logger.info("\nDecrypting the encrypted message...");
      session.decryptInit(encryptDecryptMechanism, (Key) createdObjects[indexOfGeneratedAESKey]);
      byte[] dec_data = session.decrypt(encData);
      logger.info("Data was decrypted successfully");
      logger.info("Decrypted message: {}", byteArrayToHexString(dec_data));

      // Compare the original message with decrypted one
      if (Arrays.equals(dec_data, testData)) {
        logger.info("Decrypted data matched with the main plain data.");
      } else {
        logger.error("ERROR, Mismatch decrypted data with main plain data!");
        return false;
      }

    } catch (Exception e) {
      logger.error("", e);
      return false;
    }

    return true;
  }

  public boolean signVerifyTest() {
    int i = 150;
    logger.info("Signing a random message using the generated RSA key-pair...");

    try {
      byte[] testData = session.generateRandom(i);
      logger.info("Generated random message: {}", byteArrayToHexString(testData));

      // Sign
      Mechanism signVerifyMechanism = new Mechanism(PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS);
      signVerifyMechanism.setParameters(
          new RSAPkcsPssParameters(
              new Mechanism(PKCS11Constants.CKM_SHA256), PKCS11Constants.CKG_MGF1_SHA256, 0));

      logger.info("Signing the message...");
      session.signInit(signVerifyMechanism, (Key) createdObjects[indexOfGeneratedRSAPrivateKey]);
      byte[] signature = session.sign(testData);
      logger.info("Data is signed successfully");
      logger.info("Signature of the message: {}", byteArrayToHexString(signature));

      // Verify
      logger.info("Verifying the signature...");
      session.verifyInit(signVerifyMechanism, (Key) createdObjects[indexOfGeneratedRSAPublicKey]);
      session.verify(testData, signature);
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }

    // If no exception happens, it means that the signature was valid
    logger.info("The signature is valid.");
    return true;
  }

  public boolean deleteCreatedObjectsInCurrentSession() {
    try {
      for (int i = 0; i < currentObjectIndex; ++i) {
        session.destroyObject(createdObjects[i]);
        createdObjects[i] = null;
      }
    } catch (Exception e) {
      logger.error("Cannot delete the created object(s)!", e);
      return false;
    }
    return true;
  }

  public boolean logout() {
    try {
      session.logout();
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }

    return true;
  }

  public boolean closeSession() {
    try {
      session.closeSession();
    } catch (Exception e) {
      logger.error("", e);
      return false;
    }

    return true;
  }

  public boolean Finalize_PKCS11_Library() {
    try {
      p11.finalize(null);
    } catch (Exception e) {
      logger.error("", e);
      return false;
    } finally {
      slotID = -1;
      token = null;
      session = null;
      p11 = null;

      createdObjects = null;
      currentObjectIndex = 0;
      indexOfGeneratedAESKey = -1;
      indexOfGeneratedRSAPublicKey = -1;
      indexOfGeneratedRSAPrivateKey = -1;
    }
    return true;
  }

  public String messageDigestSHA256(String inputData)
  {
    if (session == null)
      return ": You are not connected to a partition.";

    try
    {
      Mechanism digestMechanism = new Mechanism(PKCS11Constants.CKM_SHA256);

      // Calculate digest
      session.digestInit(digestMechanism);
      byte[] digest = session.digest(inputData.getBytes(StandardCharsets.UTF_8));
      try (Formatter formatter = new Formatter()) {
        for (byte b : digest) {
          formatter.format("%02x", b);
        }
        String digStr = formatter.toString();
        logger.info("Message digest (SHA256): {}", digStr);
        return digStr;
        }
    }
    catch(Exception e)
    {
      logger.error("", e);
      return null;
    }
  }

  private String byteArrayToHexString(byte[] input) {
    StringBuilder sb = new StringBuilder(input.length * 2);
    for (byte b : input) sb.append(String.format("%02X", b));
    return sb.toString();
  }
}
