# 🌐 Custom Domain Setup Guide

Complete guide untuk setup custom domain di Temp Email Bot.

## 📋 Prerequisites

### Requirements:
- ✅ **Premium Account** - Custom domain adalah Premium feature
- ✅ **Domain Ownership** - Kamu harus punya domain sendiri
- ✅ **Admin Approval** - Request harus disetujui admin (@kakatiri)
- ✅ **DNS Access** - Bisa edit DNS records domain kamu

---

## 🚀 Step-by-Step Setup

### Step 1: Request Custom Domain

**Command:**
```
/requestdomain yourdomain.com Optional note here
```

**Example:**
```
/requestdomain mybusiness.com For my online business
/requestdomain myshop.co.id E-commerce store
```

**Bot Response:**
```
✅ Domain Request Submitted!

📧 Domain: yourdomain.com
📝 Note: For my online business
📅 Submitted: 2024-02-07 10:30

⏳ Your request is being reviewed by admin.
   You'll be notified when approved.
```

**What Happens:**
- ✅ Request saved to database
- ✅ Admin (@kakatiri) gets notification
- ⏳ Wait for admin approval (usually 1-24 hours)

---

### Step 2: Admin Review (Admin Side)

**Admin sees notification:**
```
📬 New Custom Domain Request

📧 Domain: yourdomain.com
👤 User: @username (Premium ⭐)
📝 Note: For my online business
📅 Time: 2024-02-07 10:30

Buttons:
[✅ Approve] [❌ Reject] [ℹ️ Domain Info]
```

**Admin Actions:**
- **Approve**: `/approvedomain yourdomain.com Approved for business use`
- **Reject**: `/rejectdomain yourdomain.com Domain flagged as spam`

---

### Step 3: User Gets Approval Notification

**If Approved:**
```
🎉 Domain Request APPROVED!

📧 Domain: yourdomain.com
✅ Approved by: @kakatiri
📝 Note: Approved for business use

Next Steps:
1️⃣ Setup DNS records: /setupdomain yourdomain.com
2️⃣ Wait 10-30 minutes for DNS propagation
3️⃣ Request verification: /verifydomain yourdomain.com
4️⃣ Wait for admin to activate
5️⃣ Start using your custom domain!
```

**If Rejected:**
```
❌ Domain Request REJECTED

📧 Domain: yourdomain.com
📝 Reason: [Admin's reason]

💬 Questions? Contact @kakatiri
```

---

### Step 4: Setup DNS Records

**Get Instructions:**
```
/setupdomain yourdomain.com
```

**Bot Provides:**
```
🔧 Panduan Setup DNS untuk: yourdomain.com

Add these records to your DNS:

1️⃣ MX Record (Mail Exchange)
━━━━━━━━━━━━━━━
Type: MX
Name: @ (or leave empty)
Value: route.cloudflare.net
Priority: 10
TTL: Auto or 3600

2️⃣ TXT Record (Verification)
━━━━━━━━━━━━━━━
Type: TXT
Name: _emailverify
Value: tempbot-verify-abc123xyz
TTL: Auto or 3600

⏱️ Important:
• DNS changes take 10-30 minutes (sometimes 24 hours)
• Make sure all records are correct
• If unsure, screenshot and contact @kakatiri
```

**How to Add DNS Records:**

#### **Option A: Cloudflare (Recommended)**
1. Login to Cloudflare Dashboard
2. Select your domain
3. Go to **DNS** → **Records**
4. Click **Add Record**
5. Add MX record:
   - Type: `MX`
   - Name: `@`
   - Mail server: `route.cloudflare.net`
   - Priority: `10`
6. Click **Add Record** again
7. Add TXT record:
   - Type: `TXT`
   - Name: `_emailverify`
   - Content: `tempbot-verify-abc123xyz` (from bot)
8. Click **Save**
9. Wait 10-30 minutes

#### **Option B: GoDaddy**
1. Login to GoDaddy
2. My Products → Domain → Manage DNS
3. Add Record → MX:
   - Host: `@`
   - Points to: `route.cloudflare.net`
   - Priority: `10`
   - TTL: `1 hour`
4. Add Record → TXT:
   - Host: `_emailverify`
   - TXT Value: `tempbot-verify-abc123xyz`
   - TTL: `1 hour`
5. Save
6. Wait 10-30 minutes

#### **Option C: Namecheap**
1. Login to Namecheap
2. Domain List → Manage → Advanced DNS
3. Add New Record → Mail Settings:
   - Type: `MX Record`
   - Host: `@`
   - Value: `route.cloudflare.net`
   - Priority: `10`
4. Add New Record:
   - Type: `TXT Record`
   - Host: `_emailverify`
   - Value: `tempbot-verify-abc123xyz`
5. Save
6. Wait 10-30 minutes

---

### Step 5: Request Verification

**After DNS Setup (wait 10-30 minutes):**
```
/verifydomain yourdomain.com
```

**Bot Response:**
```
✅ Verification Request Sent!

📧 Domain: yourdomain.com

Admin will check your DNS setup.
You'll be notified when domain is activated.

⏱️ Processing Time: Usually 10 minutes - 24 hours

💡 Tips:
• Make sure DNS has propagated (10-30 minutes)
• Check DNS: https://dnschecker.org
• If urgent, contact @kakatiri
```

**What Happens:**
- ✅ Admin gets notification
- 🔍 Admin checks DNS manually
- ✅ Admin activates if DNS correct

---

### Step 6: Admin Verifies & Activates

**Admin checks DNS:**
```
/checkdomain yourdomain.com

Response:
🔍 DNS Check: yourdomain.com

MX Record:
✅ Found: route.cloudflare.net
✅ Priority: 10

TXT Verification:
✅ Found: tempbot-verify-abc123xyz
✅ Match: Correct verification code

Status: ✅ Ready to activate
```

**Admin activates:**
```
/activatedomain yourdomain.com
```

---

### Step 7: Domain Activated!

**You Get Notification:**
```
🎉 DOMAIN ACTIVATED!

📧 Domain: yourdomain.com
✅ Status: Active

Your custom domain is now ready!

You can create emails:
/create sales@yourdomain.com
/create support@yourdomain.com
/create info@yourdomain.com

✨ Enjoy your custom domain!
```

**Now You Can:**
- ✅ Create unlimited emails: `sales@yourdomain.com`, `support@yourdomain.com`, etc.
- ✅ Receive emails in real-time
- ✅ Use professional email addresses
- ✅ Full brand identity

---

## 🔍 Check Domain Status

**View all your domains:**
```
/mydomains
```

**Example Output:**
```
📋 Custom Domains Kamu

🟢 yourbusiness.com
   Status: Active
   Requested: 2024-02-01
   ✅ Active since: 2024-02-02

⏳ myshop.com
   Status: Pending Approval
   Requested: 2024-02-07
   
━━━━━━━━━━━━━━━
Total: 2 domain(s)

Buttons:
[📊 Stats yourbusiness.com]
[🔙 Menu Utama]
```

---

## 🛠️ Troubleshooting

### Issue 1: DNS Not Propagating

**Problem:** DNS changes tidak terdeteksi

**Solutions:**
1. **Wait longer** - DNS propagation bisa 24-48 jam
2. **Check DNS globally**: https://dnschecker.org
3. **Clear DNS cache**:
   ```bash
   # Windows
   ipconfig /flushdns
   
   # Mac/Linux
   sudo dscacheutil -flushcache
   ```
4. **Verify records di registrar dashboard**

### Issue 2: MX Record Not Found

**Problem:** Bot tidak detect MX record

**Solutions:**
1. Make sure `Name` is `@` (not blank, not domain name)
2. Value must be **exactly**: `route.cloudflare.net`
3. Priority: `10`
4. Remove other MX records (jika ada)
5. Save and wait 30 minutes

### Issue 3: TXT Record Not Found

**Problem:** Verification TXT record tidak ketemu

**Solutions:**
1. Name must be **exactly**: `_emailverify`
2. Value must match code from bot (case-sensitive!)
3. Copy-paste value from bot (jangan ketik manual)
4. No quotes di value
5. TTL: 3600 atau Auto
6. Save and wait 30 minutes

### Issue 4: Request Rejected

**Problem:** Admin reject request

**Solutions:**
1. Baca rejection reason carefully
2. Contact admin @kakatiri for clarification
3. Fix issue mentioned in reason
4. Request again dengan domain berbeda atau fix issue

### Issue 5: Cannot Create Email with Custom Domain

**Problem:** Error saat `/create sales@mydomain.com`

**Check:**
1. Domain status: `/mydomains` - must be **Active** (🟢)
2. Spelling: Pastikan domain name exact sama
3. DNS: Check if DNS still active
4. Contact admin jika masih error

---

## 📞 Support

Need help with custom domain setup?

- 💬 **Contact Admin**: @kakatiri on Telegram
- 📚 **DNS Guide**: Share your registrar name for specific guide
- 🐛 **Report Issues**: Include domain name and error message
- 📧 **Email**: Include screenshots of DNS settings

---

## ⭐ Upgrade to Premium

Want to use custom domain? Upgrade to Premium!

**Contact**: @kakatiri

**Premium Benefits:**
- ✅ 1 Custom Domain
- ✅ Unlimited Emails
- ✅ Unlimited 2FA Secrets
- ✅ Priority Support
- ✅ No Ads

---

## 📊 Examples

### E-Commerce Store
```
Domain: myshop.com
Emails:
- orders@myshop.com
- support@myshop.com
- info@myshop.com
```

### Business
```
Domain: mybusiness.com
Emails:
- sales@mybusiness.com
- contact@mybusiness.com
- team@mybusiness.com
```

### Agency
```
Domain: myagency.co.id
Emails:
- hello@myagency.co.id
- projects@myagency.co.id
- admin@myagency.co.id
```

---

**Made with ❤️ by @kakatiri**
