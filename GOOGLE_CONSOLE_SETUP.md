# Google Cloud Console Setup - Step by Step

## ⚠️ IMPORTANT: DO NOT USE LOCALHOST!

Google Cloud Console **BLOCKS** all localhost URLs. You **MUST** use a tunnel URL.

---

## Step-by-Step Instructions

### Step 1: Get Your Tunnel URL

1. Make sure your tunnel is running:
   ```bash
   npx localtunnel --port 5050
   ```

2. Copy the URL it gives you. It will look like:
   ```
   https://abc123.loca.lt
   ```

### Step 2: Go to Google Cloud Console

1. Visit: https://console.cloud.google.com/apis/credentials
2. Click on your OAuth 2.0 Client ID (or create a new one)
3. Scroll down to **"Authorized redirect URIs"**

### Step 3: Add ONLY the Tunnel URL

**IMPORTANT:** Add this EXACT format (use YOUR tunnel URL):

```
https://abc123.loca.lt/api/auth/google/callback
```

**DO NOT ADD:**
- ❌ `http://localhost:5050/api/auth/google/callback`
- ❌ `https://localhost:5050/api/auth/google/callback`
- ❌ `http://127.0.0.1:5050/api/auth/google/callback`
- ❌ `https://127.0.0.1:5050/api/auth/google/callback`

**ONLY ADD:**
- ✅ `https://abc123.loca.lt/api/auth/google/callback` (your tunnel URL)

### Step 4: Save

Click **"Save"** at the bottom of the page.

### Step 5: Update Your .env File

Open `lumra/.env` and make sure it has:

```
GOOGLE_CLIENT_ID=your-client-id-from-google
GOOGLE_CLIENT_SECRET=your-client-secret-from-google
GOOGLE_CALLBACK_URL=https://abc123.loca.lt/api/auth/google/callback
```

(Use YOUR tunnel URL, not the example)

### Step 6: Restart Backend

Restart your backend server for changes to take effect.

---

## Common Mistakes

### ❌ Mistake 1: Adding localhost
**Error:** "Invalid URL: cannot contain a localhost domain"
**Fix:** Remove any localhost URLs. Only use the tunnel URL.

### ❌ Mistake 2: Using http instead of https
**Error:** Redirect URI mismatch
**Fix:** Tunnel URLs use `https://`, not `http://`

### ❌ Mistake 3: Missing /api/auth/google/callback
**Error:** Redirect URI mismatch
**Fix:** The full path must be: `https://your-tunnel.loca.lt/api/auth/google/callback`

### ❌ Mistake 4: URL doesn't match .env file
**Error:** Redirect URI mismatch
**Fix:** The URL in Google Console must match EXACTLY what's in `GOOGLE_CALLBACK_URL` in your `.env` file

---

## Quick Checklist

- [ ] Tunnel is running (`npx localtunnel --port 5050`)
- [ ] Copied the tunnel URL (e.g., `https://abc123.loca.lt`)
- [ ] Added to Google Console: `https://abc123.loca.lt/api/auth/google/callback`
- [ ] **NO localhost URLs in Google Console**
- [ ] Updated `.env` file with the same URL
- [ ] Restarted backend server
- [ ] Visited `/tunnel-test` to activate tunnel

---

## Still Having Issues?

If you're still getting errors:

1. **Double-check the URL format:**
   - Must start with `https://`
   - Must end with `/api/auth/google/callback`
   - Must match exactly in both Google Console and `.env`

2. **Try ngrok instead:**
   - Sign up at https://ngrok.com
   - Run: `ngrok http 5050`
   - Use the ngrok URL (more reliable than localtunnel)

3. **Check your tunnel is active:**
   - Visit: `https://your-tunnel.loca.lt/tunnel-test`
   - Should see "Tunnel is Active!" message


