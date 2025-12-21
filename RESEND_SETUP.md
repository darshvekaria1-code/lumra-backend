# Resend Email Setup Guide

## Why Resend?

Resend is a modern email API that's much more reliable than SMTP for cloud platforms like Render. It's faster, doesn't timeout, and works perfectly with serverless/cloud deployments.

## Quick Setup (5 minutes)

### Step 1: Get Resend API Key

1. Go to: https://resend.com
2. Click **Sign Up** (free account)
3. Verify your email
4. Go to **API Keys** in dashboard
5. Click **Create API Key**
6. Name it: `Lumra Backend`
7. **Copy the API key** (starts with `re_`)

### Step 2: Add to Render

1. Go to Render Dashboard → Your Service → Environment
2. Click **Add Environment Variable**
3. Add:
   - **Key:** `RESEND_API_KEY`
   - **Value:** `[paste your Resend API key]`
4. (Optional) Add:
   - **Key:** `RESEND_FROM_EMAIL`
   - **Value:** `onboarding@resend.dev` (default, or use your verified domain)
5. (Optional) Add:
   - **Key:** `RESEND_TO_EMAIL`
   - **Value:** `darshvekaria1@gmail.com` (default)
6. Click **Save Changes**
7. Render will auto-redeploy

### Step 3: Verify Domain (Optional but Recommended)

1. In Resend dashboard, go to **Domains**
2. Add your domain (e.g., `lumraedu.com`)
3. Add DNS records as instructed
4. Once verified, update `RESEND_FROM_EMAIL` to use your domain

## Free Tier Limits

- **100 emails/day** (free tier)
- **3,000 emails/month** (free tier)
- Perfect for demo key requests!

## Testing

After setup, test the demo key request form. You should:
1. See `[Email] ✅ Email sent successfully via Resend!` in logs
2. Receive email at darshvekaria1@gmail.com within seconds

## Troubleshooting

**Email not sending?**
- Check Render logs for Resend errors
- Verify API key is correct (starts with `re_`)
- Check Resend dashboard for delivery status

**Need more emails?**
- Upgrade Resend plan (starts at $20/month for 50,000 emails)
- Or keep using file logging as backup




