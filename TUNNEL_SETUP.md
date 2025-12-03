# Tunnel Setup for Google OAuth

## The Problem
Localtunnel requires you to **visit the URL in a browser first** to activate it. If you don't, you'll get "missing loca domain" errors.

## Quick Fix Steps

### Step 1: Start the Tunnel
Open a **new terminal** and run:
```bash
cd lumra
npx localtunnel --port 5050
```

You'll see something like:
```
your url is: https://abc123.loca.lt
```

### Step 2: Activate the Tunnel
**IMPORTANT:** Before using OAuth, visit this URL in your browser:
```
https://abc123.loca.lt/tunnel-test
```

This activates the tunnel. You should see a green "Tunnel is Active!" message.

### Step 3: Configure Google OAuth
1. In Google Cloud Console, add this redirect URI:
   ```
   https://abc123.loca.lt/api/auth/google/callback
   ```
   (Use YOUR tunnel URL, not this example)

2. Update your `lumra/.env` file:
   ```
   GOOGLE_CLIENT_ID=your-client-id
   GOOGLE_CLIENT_SECRET=your-client-secret
   GOOGLE_CALLBACK_URL=https://abc123.loca.lt/api/auth/google/callback
   ```

3. Restart your backend server

### Step 4: Test OAuth
Now try the Google login button - it should work!

---

## Important Notes

⚠️ **Keep the tunnel terminal open** - if you close it, the tunnel stops working

⚠️ **The URL changes each time** - if you restart the tunnel, you'll get a new URL and need to update Google Console

⚠️ **Activate first** - Always visit `/tunnel-test` before using OAuth

---

## Alternative: Use ngrok (More Reliable)

If localtunnel keeps giving you issues, use ngrok instead:

### Step 1: Install ngrok
1. Sign up at https://ngrok.com (free)
2. Download ngrok
3. Run: `ngrok config add-authtoken YOUR_TOKEN`

### Step 2: Start ngrok
```bash
ngrok http 5050
```

### Step 3: Use the ngrok URL
- Copy the `Forwarding` URL (like `https://abc123.ngrok-free.app`)
- Use this in Google Console and `.env` file
- No activation needed - ngrok works immediately!

---

## Troubleshooting

### "missing loca domain" error
→ Visit `/tunnel-test` first to activate the tunnel

### "redirect_uri_mismatch" error
→ Make sure the URL in Google Console matches EXACTLY what's in `.env`

### Tunnel stops working
→ Keep the tunnel terminal window open. If it closes, restart it and update Google Console with the new URL.


