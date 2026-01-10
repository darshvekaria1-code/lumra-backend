# 🚂 Deploy Backend to Railway

## Step-by-Step Guide

### 1. Prepare Your Repository

Make sure your `lumra` directory has:
- ✅ `package.json` with `start` script
- ✅ `server.js` as the main file
- ✅ `railway.json` (already created)

### 2. Sign Up & Connect Railway

1. Go to https://railway.app
2. Sign up with GitHub
3. Click **"New Project"**
4. Select **"Deploy from GitHub repo"**
5. Choose your repository
6. Railway will detect it's a Node.js project

### 3. Configure the Service

1. Click on your service
2. Go to **Settings** → **Root Directory**
3. Set root directory to: `lumra`
4. Railway will auto-detect:
   - Build Command: `npm install`
   - Start Command: `npm start`

### 4. Set Environment Variables

Go to **Variables** tab and add:

```bash
NODE_ENV=production
PORT=5050
CORS_ORIGINS=https://eluralearning.com,https://www.eluralearning.com
GOOGLE_CALLBACK_URL=https://api.eluralearning.com/api/auth/google/callback
OPENAI_API_KEY=your-actual-openai-key
ANTHROPIC_API_KEY=your-actual-anthropic-key
JWT_SECRET=generate-a-random-32-char-string-here
SESSION_SECRET=generate-another-random-32-char-string-here
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
DEV_USERNAME=developer
DEV_PASSWORD=change-this-to-secure-password
```

**Generate secrets:**
```bash
# On Mac/Linux:
openssl rand -base64 32

# Or use online generator:
# https://www.random.org/strings/
```

### 5. Set Custom Domain

1. Go to **Settings** → **Networking**
2. Click **"Add Domain"**
3. Enter: `api.eluralearning.com`
4. Railway will show you DNS records to add

### 6. Configure DNS

In your domain registrar (GoDaddy, Namecheap, etc.):

1. Add a **CNAME** record:
   - **Host/Name**: `api`
   - **Value/Target**: [Railway-provided domain].railway.app
   - **TTL**: 3600 (or default)

2. Wait for DNS propagation (5 minutes to 48 hours)

### 7. Verify Deployment

1. Check Railway logs - should show: `Server running on port 5050`
2. Visit: `https://api.eluralearning.com/health`
3. Should return: `{ "status": "ok" }`

### 8. Update Frontend

In **Vercel Dashboard** → Your Project → Settings → Environment Variables:

Add/Update:
```
VITE_LUMRA_API_BASE=https://api.eluralearning.com
```

Then **redeploy** your frontend.

## Troubleshooting

**Backend not starting?**
- Check Railway logs
- Verify PORT is set to 5050
- Check if all environment variables are set

**CORS errors?**
- Make sure `CORS_ORIGINS` includes `https://eluralearning.com`
- Check browser console for exact error

**DNS not working?**
- Wait longer (up to 48 hours)
- Check DNS propagation: https://dnschecker.org
- Verify CNAME record is correct

## Cost

Railway offers:
- **Free tier**: $5 credit/month (usually enough for small projects)
- **Hobby plan**: $5/month for more resources

Your backend should run fine on the free tier!

