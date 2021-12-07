package ir.com.isc.hsm.iaik;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class IaikApplication {
  private static final Logger logger = LoggerFactory.getLogger("IaikApplication");
  private static final String GEN_SYM_KEY_LABEL = "PAYESH-SYM-KEY-IAIK";
  private static final String IMP_SYM_KEY_LABEL = "PAYESH-IMP-AES-KEY-IAIK";
  private static final String ASYM_PUBLIC_KEY_LABEL = "PAYESH-GEN-RSA-PUB-KEY-IAIK";
  private static final String ASYM_PRIVATE_KEY_LABEL = "PAYESH-GEN-RSA-PRV-KEY-IAIK";
  private static final String UNKNOWN_KEY_LABEL = "UNKNOWN_OBJECT_LABEL_IAIK";
  private static final String USER_PIN = "1234123412341234";
  private static final byte[] IMP_SYM_KEY_VALUE = {
    (byte) 0x11,
    (byte) 0x22,
    (byte) 0x33,
    (byte) 0x44,
    (byte) 0x55,
    (byte) 0x66,
    (byte) 0x77,
    (byte) 0x88,
    (byte) 0xAA,
    (byte) 0xBB,
    (byte) 0xCC,
    (byte) 0xDD,
    (byte) 0xEE,
    (byte) 0xFF,
    (byte) 0x00,
    (byte) 0x11,
    (byte) 0xDE,
    (byte) 0xAD,
    (byte) 0xBE,
    (byte) 0xEF,
    (byte) 0xDE,
    (byte) 0xAD,
    (byte) 0xBE,
    (byte) 0xEF,
    (byte) 0xDE,
    (byte) 0xAD,
    (byte) 0xBE,
    (byte) 0xEF,
    (byte) 0xDE,
    (byte) 0xAD,
    (byte) 0xBE,
    (byte) 0xEF
  };

  public static void main(String[] args) {
    PKCS11Controller pkcs11Controller = new PKCS11Controller();

    String modulePath = pkcs11Controller.getModulePathBaseOnOS();

    // Initialization
    if (!pkcs11Controller.initializePKCS11Library(modulePath)) {
      logger.error("ERROR in initialization!");
      return;
    }
    logger.info("The pkcs11 library was initialized successfully.");

    // Get slot list and select the first slot-ID
    if (!pkcs11Controller.getFirstAvailableSlotID()) {
      logger.error("ERROR in getFirstAvailableSlotID!");
      return;
    }

    // Show token information for the first slot-ID
    if (!pkcs11Controller.showTokenInfo()) {
      logger.error("ERROR in getTokenInfo!");
      return;
    }

    // Open session
    if (!pkcs11Controller.openSession()) {
      logger.error("Cannot open the session!");
      return;
    }
    logger.info("Open User rw-session to slot {} successfully.", pkcs11Controller.getSlotID());

    // Login
    if (!pkcs11Controller.login(USER_PIN)) {
      logger.error("Cannot login to the session");
      return;
    }
    logger.info("Logged in successfully.");

    // Generate sample AES key
    logger.info("Generating an AES key...");
    if (!pkcs11Controller.generateAESKey(GEN_SYM_KEY_LABEL)) {
      logger.error("Cannot generate AES key!");
      return;
    }

    // Generate sample RSA key-pair
    logger.info("Generating an RSA key pair...");
    if (!pkcs11Controller.generateRSAKeyPair(ASYM_PUBLIC_KEY_LABEL, ASYM_PRIVATE_KEY_LABEL)) {
      logger.error("Cannot generate RSA key-pair!");
      pkcs11Controller.deleteCreatedObjectsInCurrentSession();
      return;
    }

    // Create sample object
    logger.info("Importing an AES key...");
    if (!pkcs11Controller.createObject(IMP_SYM_KEY_LABEL, IMP_SYM_KEY_VALUE)) {
      logger.error("Cannot import the AES key!");
      pkcs11Controller.deleteCreatedObjectsInCurrentSession();
      return;
    }

    // Find object
    logger.info("Trying to find previously generated AES key...");
    if (!pkcs11Controller.findObjectByLabel(GEN_SYM_KEY_LABEL)) {
      logger.error("An error occurs while trying to find object!");
      pkcs11Controller.deleteCreatedObjectsInCurrentSession();
      return;
    }

    // Find a not-existed object
    logger.info("Trying to find an object that does not exist...");
    if (!pkcs11Controller.findObjectByLabel(UNKNOWN_KEY_LABEL)) {
      logger.error("An error occurs while trying to find object!");
      pkcs11Controller.deleteCreatedObjectsInCurrentSession();
      return;
    }

    // Get some attributes from public key
    if (!pkcs11Controller.getAttributesTest()) {
      logger.error("Cannot get attributes from public key!");
      pkcs11Controller.deleteCreatedObjectsInCurrentSession();
      return;
    }

    // Encrypt a random message, decrypt it, and compare the decrypted message with the original one
    if (!pkcs11Controller.encryptDecryptTest()) {
      logger.error("Something wrong happened in encrypt-decrypt test!");
      pkcs11Controller.deleteCreatedObjectsInCurrentSession();
      return;
    }

    // Sign a random message and verify the signature
    if (!pkcs11Controller.signVerifyTest()) {
      logger.error("Something wrong happened in sign-verify test!");
      pkcs11Controller.deleteCreatedObjectsInCurrentSession();
      return;
    }

    // Hash message
    pkcs11Controller.messageDigestSHA256(UNKNOWN_KEY_LABEL);

    // Destroy objects
    pkcs11Controller.deleteCreatedObjectsInCurrentSession();

    logger.info("Finalization...");
    // logout
    if (!pkcs11Controller.logout()) {
      logger.error("Cannot loged out from session");
      return;
    }
    logger.info("Logged out successfully.");

    // Close session
    if (!pkcs11Controller.closeSession()) {
      logger.error("Cannot close the session");
      return;
    }
    logger.info("Session was closed successfully.");

    // finalize
    if (!pkcs11Controller.Finalize_PKCS11_Library()) {
      logger.error("Cannot finalize the library!");
      return;
    }
    logger.info("The library was finalized successfully.");
  }
}
