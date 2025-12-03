# 🚀 Complete Setup Steps - Do This Now!

## ✅ Step 1: ngrok is Already Extracted!
ngrok.exe is ready at: `C:\ngrok\ngrok.exe`

---

## 📝 Step 2: Get Your ngrok Authtoken

1. **Sign up for ngrok** (if you haven't):
   - Go to: https://dashboard.ngrok.com/signup
   - Sign up with your email
   - Verify your email

2. **Get your authtoken**:
   - Go to: https://dashboard.ngrok.com/get-started/your-authtoken
   - **Copy your authtoken** (long string of characters)

3. **Configure ngrok**:
   ```powershell
   cd C:\Users\forty\cs_ia_inventory_payroll\CleverraX\lumra
   .\configure-ngrok.ps1
   ```
   - Paste your authtoken when prompted

---

## 🖥️ Step 3: Make Sure Backend is Running

Open a terminal and run:
```powershell
cd C:\Users\forty\cs_ia_inventory_payroll\CleverraX\lumra
npm run dev
```

Keep this terminal open!

---

## 🌐 Step 4: Start ngrok Tunnel

Open a **NEW** terminal and run:
```powershell
cd C:\Users\forty\cs_ia_inventory_payroll\CleverraX\lumra
.\start-ngrok.ps1
```

You'll see something like:
```
Forwarding   https://abc123.ngrok-free.app -> http://localhost:5050
```

**📋 COPY THIS URL:** `https://abc123.ngrok-free.app`

**⚠️ KEEP THIS TERMINAL OPEN!**

---

## 🔑 Step 5: Update Google Console

1. Go to: https://console.cloud.google.com/apis/credentials
2. Click on your OAuth 2.0 Client ID
3. Fill in:

   **Application home page:**
   ```
   https://abc123.ngrok-free.app
   ```
   (Use YOUR ngrok URL)

   **Authorized redirect URIs:**
   ```
   https://abc123.ngrok-free.app/api/auth/google/callback
   ```
   (Use YOUR ngrok URL)

4. Click **"Save"**

---

## 📝 Step 6: Update .env File

Run this script:
```powershell
.\update-env-with-ngrok.ps1
```

Enter your ngrok URL when prompted (e.g., `https://abc123.ngrok-free.app`)

**OR** manually edit `lumra/.env` and set:
```
GOOGLE_CALLBACK_URL=https://abc123.ngrok-free.app/api/auth/google/callback
```
(Use YOUR ngrok URL)

---

## 🔄 Step 7: Restart Backend

1. Stop your backend (Ctrl+C in the backend terminal)
2. Start it again:
   ```powershell
   npm run dev
   ```

---

## ✅ Step 8: Test It!

1. Visit: `https://abc123.ngrok-free.app/tunnel-test`
   (Should show "Tunnel is Active!")

2. Go to your frontend: `http://localhost:5173`

3. Click **"Continue with Google"** - it should work now! 🎉

---

## 📋 Quick Command Reference

```powershell
# Configure ngrok authtoken
.\configure-ngrok.ps1

# Start ngrok tunnel
.\start-ngrok.ps1

# Update .env with ngrok URL
.\update-env-with-ngrok.ps1
```

---

## ⚠️ Important Notes

- **Keep ngrok running** - Don't close the terminal running ngrok
- **URL changes** - Free ngrok URLs change each time you restart. If you restart ngrok, update Google Console and .env with the new URL
- **Backend must be running** - Make sure your backend is running on port 5050 before starting ngrok

---

## 🆘 Troubleshooting

### "ngrok not found"
→ Make sure ngrok.exe is at `C:\ngrok\ngrok.exe`

### "authtoken invalid"
→ Double-check you copied the correct token from the ngrok dashboard

### "port 5050 already in use"
→ Make sure your backend is running on port 5050

### Google OAuth still not working
→ Make sure:
- ngrok is running (keep that terminal open!)
- The URL in Google Console matches EXACTLY what's in your .env file
- You restarted the backend after updating .env



