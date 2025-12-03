# Google OAuth - App Domain Setup

## What to Put in Each Field

### 1. Application home page
**Put your tunnel URL here:**
```
https://abc123.loca.lt
```
(Use YOUR tunnel URL - just the base URL, no `/api/auth/google/callback`)

**Purpose:** This is the URL that shows on the Google consent screen. Users will see this as your app's home page.

---

### 2. Authorized redirect URIs (Different Section)
**This is in a DIFFERENT section** (usually under "Authorized redirect URIs" or "Redirect URIs")

**Put the full callback URL:**
```
https://abc123.loca.lt/api/auth/google/callback
```

**Purpose:** This is where Google sends users back after they log in.

---

## Quick Summary

| Field | What to Put | Example |
|-------|-------------|---------|
| **Application home page** | Your tunnel base URL | `https://abc123.loca.lt` |
| **Authorized redirect URIs** | Full callback path | `https://abc123.loca.lt/api/auth/google/callback` |

---

## Important Notes

- ✅ Both fields use your **tunnel URL** (not localhost)
- ✅ Both use **https://** (not http://)
- ✅ The home page is just the base URL
- ✅ The redirect URI includes `/api/auth/google/callback`

---

## If You Don't Have a Home Page

If you don't have a specific home page, you can use:
- Your tunnel URL: `https://abc123.loca.lt`
- Or a placeholder: `https://abc123.loca.lt/` (with trailing slash)

The important part is that it's a valid URL that Google can verify.


