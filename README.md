# 🛡️ AMAN Cashier - Online License Server (Vercel Ready)

لوحة تحكم وسيرفر التراخيص السحابي الرسمي لنظام **AMAN CASHIER**، مجهز للنشر المباشر على **Vercel** مجاناً 100%.

---

## 🚀 طريقة الرفع والنشر على Vercel في دقيقة واحدة:

### الطريقة الأولى (باستخدام Vercel CLI):
1. افتح التيرمنال داخل هذا المجلد:
   ```bash
   cd "license-server-vercel"
   npx vercel
   ```
2. اضغط Enter وسجل دخولك ببريدك أو GitHub.
3. مبروك! ستحصل على رابط أونلاين مجاني مثل: `https://aman-license.vercel.app`

---

### الطريقة الثانية (عبر GitHub):
1. قم برفع هذا المجلد `license-server-vercel` إلى مستودع جديد على **GitHub**.
2. افتح حسابك في [vercel.com](https://vercel.com).
3. اضغط **Add New Project** ثم اختر المستودع واضغط **Deploy**.

---

## 🔗 ربط تطبيق الكاشير بالرابط السحابي الجديد:
بعد الحصول على رابط Vercel (مثال: `https://aman-license.vercel.app`):
1. افتح تطبيق الديسكتوب.
2. اضغط على **"تغيير رابط سيرفر التراخيص"** في شاشة التفعيل والصق رابط Vercel الخاص بك.
3. أو قم بوضعه كرابط افتراضي في الكود داخل `src/main/ipc/license.ts`.
