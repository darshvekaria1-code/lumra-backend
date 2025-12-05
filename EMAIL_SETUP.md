# Email Setup Guide for Demo Key Requests

## Why emails aren't being sent

The email functionality requires Gmail App Password to be configured in Render. Currently, requests are being saved to files but emails aren't being sent.

## Quick Setup Steps

### 1. Get Gmail App Password

1. Go to: https://myaccount.google.com/
2. Click **Security** (left sidebar)
3. Enable **2-Step Verification** (if not already enabled)
4. Scroll down and click **App passwords**
5. Select app: **Mail**
6. Select device: **Other (Custom name)**
7. Enter name: **Lumra Backend**
8. Click **Generate**
9. **Copy the 16-character password** (you'll need this)

### 2. Add to Render Environment Variables

1. Go to Render Dashboard: https://dashboard.render.com
2. Click on your **lumra-backend** service
3. Go to **Environment** tab
4. Click **Add Environment Variable**
5. Add these two variables:

   **Variable 1:**
   - Key: `EMAIL_USER`
   - Value: `darshvekaria1@gmail.com`

   **Variable 2:**
   - Key: `EMAIL_APP_PASSWORD`
   - Value: `[paste the 16-character app password from step 1]`

6. Click **Save Changes**
7. Render will automatically redeploy

### 3. Test

After redeployment, test the demo key request form. You should receive emails at **darshvekaria1@gmail.com**.

## Alternative: View Requests Without Email

If you don't want to set up email right now, you can view all requests:

### Option 1: Check Render Logs
- Go to Render Dashboard → Your Service → Logs
- Look for entries like: `[Demo Key Request] New request from: ...`

### Option 2: Check Files (via Render Shell)
- Requests are saved to: `demo_requests.json`
- Logs are saved to: `demo_key_requests.log`

### Option 3: Use API Endpoint (if logged in as developer)
- GET `/api/demo/requests` - Returns all demo key requests

## Troubleshooting

**Email still not working?**
1. Check Render logs for email errors
2. Verify App Password is correct (no spaces)
3. Make sure 2-Step Verification is enabled
4. Check spam folder

**Need help?**
- Check `demo_key_requests.log` file for all requests
- All requests are saved even if email fails

