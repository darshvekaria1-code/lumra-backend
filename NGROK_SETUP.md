# ngrok Setup for Google OAuth (RECOMMENDED)

## Why ngrok?
- ✅ Google OAuth accepts ngrok domains
- ✅ More reliable than localtunnel
- ✅ Free tier available
- ✅ Permanent URL (if you use the same authtoken)

---

## Step 1: Sign Up for ngrok

1. Go to: https://dashboard.ngrok.com/signup
2. Sign up for a free account
3. Verify your email

---

## Step 2: Install ngrok

### Option A: Download (Windows)
1. Go to: https://ngrok.com/download
2. Download ngrok for Windows
3. Extract the `ngrok.exe` file
4. Move it to a folder (e.g., `C:\ngrok\`)
5. Add that folder to your PATH, OR just use the full path

### Option B: Using Chocolatey (if you have it)
```powershell
choco install ngrok
```

### Option C: Using Scoop (if you have it)
```powershell
scoop install ngrok
```

---

## Step 3: Get Your Authtoken

1. Go to: https://dashboard.ngrok.com/get-started/your-authtoken
2. Copy your authtoken (looks like: `2abc123def456ghi789jkl012mno345pq_6r7s8t9u0v1w2x3y4z5`)

---

## Step 4: Configure ngrok

Open PowerShell and run:
```powershell
ngrok config add-authtoken YOUR_AUTHTOKEN_HERE
```

Replace `YOUR_AUTHTOKEN_HERE` with the token you copied.

---

## Step 5: Start ngrok

Make sure your backend is running on port 5050, then run:

```powershell
ngrok http 5050
```

You'll see something like:
```
Forwarding   https://abc123.ngrok-free.app -> http://localhost:5050
```

**Copy the `https://abc123.ngrok-free.app` URL** - this is your ngrok URL!

---

## Step 6: Configure Google OAuth

### In Google Cloud Console:

1. **Application home page:**
   ```
   https://abc123.ngrok-free.app
   ```
   (Use YOUR ngrok URL)

2. **Authorized redirect URIs:**
   ```
   https://abc123.ngrok-free.app/api/auth/google/callback
   ```
   (Use YOUR ngrok URL)

### In your `.env` file:

```
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_CALLBACK_URL=https://abc123.ngrok-free.app/api/auth/google/callback
```

(Use YOUR ngrok URL)

---

## Step 7: Restart Backend

Restart your backend server for changes to take effect.

---

## Step 8: Test

1. Visit: `https://abc123.ngrok-free.app/tunnel-test` (should work immediately)
2. Try Google login - it should work now!

---

## Important Notes

⚠️ **Keep ngrok running** - Keep the terminal with `ngrok http 5050` open

⚠️ **URL changes** - Free ngrok URLs change each time you restart. For a permanent URL, upgrade to a paid plan or use ngrok's reserved domains feature.

⚠️ **No activation needed** - Unlike localtunnel, ngrok works immediately, no need to visit a test page first.

---

## Troubleshooting

### "ngrok not found"
→ Make sure ngrok is installed and in your PATH, or use the full path to ngrok.exe

### "authtoken invalid"
→ Double-check you copied the correct token from the dashboard

### "port already in use"
→ Make sure nothing else is using port 5050, or use a different port

### Still getting domain errors
→ Make sure you're using the `https://` URL from ngrok, not `http://`


