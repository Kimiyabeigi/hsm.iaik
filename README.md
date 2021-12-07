<div dir="rtl" style="font-family: Tahoma;font-size: large">

# ReadMe 
این فایل صرفا جهت معرفی sample code ها می باشد

#IAIK
####getModulePathBaseOnOS
تعیین مسیر فایل تنظیمات HSM با توجه به نوع سیستم عامل 

####initializePKCS11Library
وصل شدن به HSM و مقدار دهی اولیه متغییرها

####getFirstAvailableSlotID
گرفتن لیست اسلاتهای HSM و انتخاب اولین اسلات بعنوان پیش فرض

####showTokenInfo
نمایش اطلاعات توکن اسلاید انتخاب شده

####openSession
باز کردن session برای کار با HSM

####login
ورود به HSM با استفاده از pin اعلام شده

####generateAESKey
ساخت کلید متقارن و ذخیره آن در HSM

####generateRSAKeyPair
ساخت کلید نامتقارن و ذخیره کلید عمومی و خصوصی در HSM

####createObject
ذخیره کلید دریافتی (کلیدی که از قبل موجود میباشد) در HSM

####findObjectByLabel
جستجوی کلید ها در HSM با استفاده از عنوان آنها 

####getAttributesTest
گرفتن خصوصیات یک کلید از HSM و نمایش آنها

####encryptDecryptTest
رمز نگاری و رمزگشایی متن با استفاده از کلید متقارن

####signVerifyTest
امضا متن و صحت سنجی امضا با استفاده از کلید نامتقارن

</div>