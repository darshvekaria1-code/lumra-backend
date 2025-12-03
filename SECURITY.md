# Security Guide for Lumra Backend

This document outlines the security measures implemented in the Lumra backend server to protect against common attacks.

## 🔒 Security Features Implemented

### 1. **Secure Cookie Configuration**

All cookies are configured with security best practices:

- **httpOnly**: `true` - Prevents JavaScript access to cookies, protecting against XSS attacks
- **secure**: `true` in production - Only sent over HTTPS connections
- **sameSite**: `'strict'` - Prevents CSRF attacks by only sending cookies with same-site requests
- **maxAge**: Set with appropriate expiration times
- **domain**: Configurable via `COOKIE_DOMAIN` environment variable

**Session Cookies:**
```javascript
cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
}
```

**JWT Token Cookies:**
```javascript
res.cookie('lumra_token', token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
})
```

### 2. **JWT Token Security**

- Tokens include `iat` (issued at) timestamp
- Tokens include `issuer` and `audience` claims
- Token expiration set to 7 days
- Tokens can be stored in:
  - Authorization header (Bearer token)
  - Secure httpOnly cookie (preferred)

### 3. **Input Validation & Sanitization**

- **Email Validation**: Regex pattern matching + length limits (max 254 chars)
- **Password Validation**: 
  - Minimum 8 characters
  - Maximum 128 characters
  - Must contain at least one letter and one number
- **Input Sanitization**: 
  - Removes potentially dangerous characters (`<`, `>`)
  - Trims whitespace
  - Limits input length to prevent DoS attacks

### 4. **Rate Limiting**

Protection against brute force and DoS attacks:

- **API Rate Limit**: 100 requests per 15 minutes per IP
- **Auth Rate Limit**: 10 requests per 15 minutes per IP (for login/signup)
- **AI Rate Limit**: 20 requests per minute per IP

### 5. **Security Headers (Helmet.js)**

Automatic security headers including:
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Strict-Transport-Security (in production)

### 6. **CORS Protection**

- Configurable allowed origins via `CORS_ORIGINS` environment variable
- Credentials support enabled for cookie-based auth
- Strict origin validation

### 7. **Password Security**

- Passwords hashed using bcrypt with 10 salt rounds
- Never stored in plain text
- Password comparison uses timing-safe comparison

### 8. **Session Security**

- Custom session name (`lumra.sid` instead of default)
- Rolling sessions (expiration resets on each request)
- Session data not stored in cookies (only session ID)
- Automatic session expiration

## 🛡️ Protection Against Common Attacks

### Cross-Site Scripting (XSS)
- ✅ httpOnly cookies prevent JavaScript access
- ✅ Input sanitization removes dangerous characters
- ✅ CSP headers restrict script sources
- ✅ Helmet.js provides XSS protection headers

### Cross-Site Request Forgery (CSRF)
- ✅ SameSite cookie attribute (`strict`)
- ✅ CORS origin validation
- ✅ Custom session names

### SQL Injection / NoSQL Injection
- ✅ No direct database queries (uses Map data structure)
- ✅ Input validation and sanitization
- ✅ Parameterized data handling

### Brute Force Attacks
- ✅ Rate limiting on authentication endpoints
- ✅ Account lockout recommendations (can be added)
- ✅ Slow password hashing (bcrypt)

### Session Hijacking
- ✅ Secure cookies (HTTPS only in production)
- ✅ httpOnly cookies (not accessible via JavaScript)
- ✅ Session expiration
- ✅ Rolling sessions

### Man-in-the-Middle (MITM)
- ✅ HTTPS enforcement in production
- ✅ Secure cookie flag
- ✅ HSTS headers (via Helmet)

## 📋 Environment Variables for Security

```bash
# Required for production
NODE_ENV=production
JWT_SECRET=your-strong-random-secret-min-32-chars
SESSION_SECRET=your-strong-random-secret-min-32-chars

# Optional security settings
COOKIE_DOMAIN=.yourdomain.com  # Restrict cookies to your domain
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

## 🔐 Best Practices Checklist

### Production Deployment

- [ ] Set `NODE_ENV=production`
- [ ] Use strong, random `JWT_SECRET` (minimum 32 characters)
- [ ] Use strong, random `SESSION_SECRET` (minimum 32 characters)
- [ ] Enable HTTPS/TLS
- [ ] Set `COOKIE_DOMAIN` if using subdomains
- [ ] Configure `CORS_ORIGINS` with specific allowed origins
- [ ] Regularly update dependencies (`npm audit`)
- [ ] Monitor logs for suspicious activity
- [ ] Implement logging and monitoring
- [ ] Set up rate limiting alerts
- [ ] Regular security audits

### Development

- [ ] Never commit `.env` file to git
- [ ] Use different secrets for dev/staging/production
- [ ] Test security features regularly
- [ ] Review dependency updates for security patches

## 🚨 Security Incident Response

If you suspect a security breach:

1. **Immediately rotate all secrets**:
   - `JWT_SECRET`
   - `SESSION_SECRET`
   - Any API keys

2. **Force logout all users**:
   - Clear all sessions
   - Invalidate all tokens

3. **Review logs** for suspicious activity

4. **Notify affected users** if data was compromised

5. **Patch vulnerabilities** and update dependencies

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

## 🔍 Monitoring & Logging

Consider implementing:
- Failed login attempt logging
- Unusual API usage alerts
- Token expiration monitoring
- Rate limit violation alerts
- Security event logging

---

**Last Updated**: {{ new Date().toISOString() }}
**Security Contact**: Update this with your security team contact


