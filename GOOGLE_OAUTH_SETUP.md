# Google OAuth Setup Guide

## Problem: "Invalid URL: cannot contain a localhost domain"

Google Cloud Console sometimes blocks `localhost` URLs. Here are **3 solutions**:

---

## ✅ Solution 1: Use `127.0.0.1` instead of `localhost` (Easiest)

### Step 1: In Google Cloud Console
1. Go to: https://console.cloud.google.com/apis/credentials
2. Create OAuth 2.0 Client ID (Web application)
3. Add this redirect URI:
   ```
   http://127.0.0.1:5050/api/auth/google/callback
   ```
   **Note:** Use `127.0.0.1` NOT `localhost`

### Step 2: Update your `.env` file
Add to `lumra/.env`:
```
GOOGLE_CLIENT_ID=your-client-id-here
GOOGLE_CLIENT_SECRET=your-client-secret-here
GOOGLE_CALLBACK_URL=http://127.0.0.1:5050/api/auth/google/callback
```

### Step 3: Restart backend
Restart your backend server.

---

## ✅ Solution 2: Use a Tunnel Service (Most Reliable)

This creates a public URL that points to your local server.

### Step 1: Install and run localtunnel
```bash
cd lumra
npx localtunnel --port 5050
```

You'll get a URL like: `https://random-name.loca.lt`

### Step 2: In Google Cloud Console
1. Go to: https://console.cloud.google.com/apis/credentials
2. Create OAuth 2.0 Client ID (Web application)
3. Add this redirect URI (use YOUR tunnel URL):
   ```
   https://random-name.loca.lt/api/auth/google/callback
   ```

### Step 3: Update your `.env` file
```
GOOGLE_CLIENT_ID=your-client-id-here
GOOGLE_CLIENT_SECRET=your-client-secret-here
GOOGLE_CALLBACK_URL=https://random-name.loca.lt/api/auth/google/callback
```

### Step 4: Keep tunnel running
- Keep the `localtunnel` terminal window open
- Restart your backend server
- Access your frontend at the tunnel URL (or keep using localhost:5173)

**Note:** The tunnel URL changes each time you restart it. For a permanent URL, use ngrok (requires signup).

---

## ✅ Solution 3: Use ngrok (Permanent URL)

### Step 1: Sign up and install ngrok
1. Sign up at: https://ngrok.com
2. Download ngrok
3. Authenticate: `ngrok config add-authtoken YOUR_TOKEN`

### Step 2: Run ngrok
```bash
ngrok http 5050
```

You'll get a URL like: `https://abc123.ngrok-free.app`

### Step 3: In Google Cloud Console
Add redirect URI:
```
https://abc123.ngrok-free.app/api/auth/google/callback
```

### Step 4: Update `.env`
```
GOOGLE_CALLBACK_URL=https://abc123.ngrok-free.app/api/auth/google/callback
```

---

## Which Solution to Use?

- **Solution 1 (127.0.0.1)**: Try this first - it's the simplest
- **Solution 2 (localtunnel)**: Use if Solution 1 doesn't work
- **Solution 3 (ngrok)**: Use if you need a permanent URL

---

## Troubleshooting

### "redirect_uri_mismatch" error
- Make sure the URL in Google Console matches EXACTLY what's in your `.env` file
- Check for trailing slashes, http vs https, port numbers

### OAuth button not working
- Make sure backend is running on port 5050
- Check that `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set in `.env`
- Restart backend after changing `.env`

### Tunnel not working
- Make sure the tunnel is running (keep terminal open)
- Check that backend is running on the port you specified
- Try a different tunnel service if one doesn't work
