# 🚀 Quick Setup Guide - Google OAuth with ngrok

## Step-by-Step Setup (Do This Now!)

### Step 1: Install ngrok ⬇️

**Option A: Download (Easiest)**
1. Go to: https://ngrok.com/download
2. Click "Download for Windows"
3. Extract `ngrok.exe` to `C:\ngrok\` (or any folder)
4. Open PowerShell and run:
   ```powershell
   cd C:\ngrok
   .\ngrok.exe version
   ```
   (If this works, ngrok is installed!)

**Option B: Using Chocolatey (if you have it)**
```powershell
choco install ngrok
```

---

### Step 2: Sign Up for ngrok Account 📝

1. Go to: https://dashboard.ngrok.com/signup
2. Sign up with your email
3. Verify your email
4. Go to: https://dashboard.ngrok.com/get-started/your-authtoken
5. **Copy your authtoken** (long string of characters)

---

### Step 3: Configure ngrok 🔧

Open PowerShell and run:
```powershell
cd C:\ngrok
.\ngrok.exe config add-authtoken YOUR_AUTHTOKEN_HERE
```
(Replace `YOUR_AUTHTOKEN_HERE` with the token you copied)

**OR** if ngrok is in your PATH:
```powershell
ngrok config add-authtoken YOUR_AUTHTOKEN_HERE
```

---

### Step 4: Start Your Backend Server 🖥️

Make sure your backend is running:
```powershell
cd C:\Users\forty\cs_ia_inventory_payroll\CleverraX\lumra
npm run dev
```

Keep this terminal open!

---

### Step 5: Start ngrok Tunnel 🌐

Open a **NEW** PowerShell window and run:
```powershell
cd C:\Users\forty\cs_ia_inventory_payroll\CleverraX\lumra
.\start-ngrok.ps1
```

**OR** if ngrok is in your PATH:
```powershell
ngrok http 5050
```

You'll see something like:
```
Forwarding   https://abc123.ngrok-free.app -> http://localhost:5050
```

**📋 COPY THIS URL:** `https://abc123.ngrok-free.app`

**⚠️ KEEP THIS TERMINAL OPEN!**

---

### Step 6: Configure Google OAuth 🔑

1. Go to: https://console.cloud.google.com/apis/credentials
2. Click on your OAuth 2.0 Client ID (or create one)
3. Fill in these fields:

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

### Step 7: Update Your .env File 📝

Open `lumra/.env` and update these lines:

```
GOOGLE_CLIENT_ID=your-client-id-from-google-console
GOOGLE_CLIENT_SECRET=your-client-secret-from-google-console
GOOGLE_CALLBACK_URL=https://abc123.ngrok-free.app/api/auth/google/callback
```

(Replace `abc123.ngrok-free.app` with YOUR ngrok URL)

---

### Step 8: Restart Backend 🔄

1. Stop your backend (Ctrl+C in the backend terminal)
2. Start it again:
   ```powershell
   npm run dev
   ```

---

### Step 9: Test It! ✅

1. Visit: `https://abc123.ngrok-free.app/tunnel-test`
   (Should show "Tunnel is Active!")

2. Go to your frontend: `http://localhost:5173`

3. Click "Continue with Google" - it should work now! 🎉

---

## Troubleshooting

### "ngrok not found"
→ Make sure ngrok.exe is in a folder and you're running it from there, OR add it to your PATH

### "authtoken invalid"
→ Double-check you copied the correct token from the ngrok dashboard

### "port 5050 already in use"
→ Make sure your backend is running on port 5050

### Google OAuth still not working
→ Make sure:
- ngrok is running (keep that terminal open!)
- The URL in Google Console matches EXACTLY what's in your .env file
- You restarted the backend after updating .env

---

## Quick Commands Reference

```powershell
# Check if ngrok is installed
.\setup-ngrok.ps1

# Start ngrok tunnel
.\start-ngrok.ps1

# Or manually:
ngrok http 5050
```

---

## Need Help?

- ngrok docs: https://ngrok.com/docs
- Google OAuth setup: See `GOOGLE_CONSOLE_SETUP.md`
- Full ngrok guide: See `NGROK_SETUP.md`


