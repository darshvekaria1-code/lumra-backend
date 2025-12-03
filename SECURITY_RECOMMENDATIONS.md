# Comprehensive Security Recommendations for Lumra

This document outlines additional security measures you can implement to protect against hackers, viruses, malware, and other threats.

## 🔒 Current Security Measures (Already Implemented)

✅ Secure cookie configuration (httpOnly, Secure, SameSite)
✅ JWT token encryption
✅ Input validation and sanitization
✅ Rate limiting
✅ CORS protection
✅ Helmet.js security headers
✅ Password hashing (bcrypt)
✅ Session security

---

## 🛡️ Additional Security Measures You Can Implement

### 1. **Dependency Security & Vulnerability Scanning**

#### npm audit & Updates
```bash
# Check for vulnerabilities
npm audit

# Fix automatically fixable issues
npm audit fix

# Update dependencies regularly
npm update

# Use automated dependency updates
npm install -D npm-check-updates
ncu -u  # Update package.json
```

#### Recommended Tools:
- **Snyk** (https://snyk.io/) - Free tier available
  - Continuous vulnerability scanning
  - Dependency monitoring
  - License compliance checking

- **GitHub Dependabot** (if using GitHub)
  - Automatic security updates
  - Dependency pull requests
  - Vulnerability alerts

- **npm audit** (built-in)
  - Regular vulnerability checks
  - Security advisories

#### Implementation:
```json
// package.json
{
  "scripts": {
    "audit": "npm audit",
    "audit:fix": "npm audit fix",
    "security:check": "npm audit && npm outdated"
  }
}
```

---

### 2. **Content Security Policy (CSP) Enhancement**

Current CSP is basic. Enhance it:

```javascript
// In server.js - enhance helmet CSP
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // Remove unsafe-inline in production
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://api.openai.com", "https://api.anthropic.com"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            upgradeInsecureRequests: process.env.NODE_ENV === "production" ? [] : null,
        },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginResourcePolicy: { policy: "same-origin" },
}))
```

---

### 3. **Request Validation & Sanitization**

#### Add express-validator:
```bash
npm install express-validator
```

#### Implementation:
```javascript
import { body, validationResult, sanitizeBody } from 'express-validator'

// Enhanced login validation
app.post("/api/auth/login", 
    authLimiter,
    [
        body('email')
            .isEmail()
            .normalizeEmail()
            .trim(),
        body('password')
            .isLength({ min: 8, max: 128 })
            .trim()
    ],
    async (req, res) => {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: "Validation failed", 
                details: errors.array() 
            })
        }
        // ... rest of login logic
    }
)
```

---

### 4. **SQL Injection Protection** (Even with NoSQL)

#### Use Parameterized Queries:
- ✅ Already safe (using Map, not database)
- ✅ Input sanitization in place
- ✅ Validation prevents injection

#### If using database later:
- Use ORM/ODM (Mongoose, Sequelize)
- Never use string concatenation for queries
- Use parameterized queries
- Validate and sanitize all inputs

---

### 5. **XSS Protection**

#### Additional Measures:

1. **DOMPurify for Frontend** (if using dangerouslySetInnerHTML):
```bash
cd color
npm install dompurify
npm install --save-dev @types/dompurify
```

```typescript
import DOMPurify from 'dompurify'

const cleanHTML = DOMPurify.sanitize(userInput)
```

2. **Output Encoding**:
- Always encode user input when displaying
- Use React's built-in escaping (it does this automatically)
- Never use `dangerouslySetInnerHTML` with user input

3. **CSP Nonces** (for inline scripts):
```javascript
// Generate nonce per request
const nonce = crypto.randomBytes(16).toString('base64')
res.locals.nonce = nonce

// In CSP:
scriptSrc: ["'self'", `'nonce-${nonce}'`]
```

---

### 6. **Rate Limiting Enhancements**

#### Current rate limits are good, but add:

```javascript
import rateLimit from 'express-rate-limit'
import RedisStore from 'rate-limit-redis'  // If using Redis

// Per-IP rate limiting (already have)
// Add: Per-user rate limiting
const userRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: async (req) => {
        if (req.user) return 200  // Logged in users: 200 requests
        return 50  // Anonymous users: 50 requests
    },
    keyGenerator: (req) => {
        return req.user ? req.user.email : req.ip
    },
    message: "Too many requests, please try again later."
})

// Add: Per-endpoint rate limiting
const aiRateLimiter = rateLimit({
    windowMs: 60 * 1000,  // 1 minute
    max: 10,  // 10 requests per minute per user
    keyGenerator: (req) => req.user ? req.user.email : req.ip,
    message: "Too many AI requests. Please slow down."
})
```

---

### 7. **Request Logging & Monitoring**

#### Add winston for logging:
```bash
npm install winston winston-daily-rotate-file
```

```javascript
import winston from 'winston'

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error' 
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log' 
        }),
        new winston.transports.DailyRotateFile({
            filename: 'logs/application-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '14d'
        })
    ],
})

// Log security events
function logSecurityEvent(type, details) {
    logger.warn('Security Event', {
        type, // 'failed_login', 'rate_limit', 'suspicious_activity'
        ...details,
        timestamp: new Date().toISOString(),
        ip: req.ip
    })
}
```

#### Log Important Events:
- Failed login attempts
- Rate limit violations
- Unusual API usage patterns
- Authentication failures
- Token validation failures

---

### 8. **Intrusion Detection System (IDS)**

#### Implement suspicious activity detection:

```javascript
// Track failed login attempts
const failedLoginAttempts = new Map()

app.post("/api/auth/login", authLimiter, async (req, res, next) => {
    const ip = req.ip
    const email = req.body.email?.toLowerCase()
    
    try {
        // ... login logic
        // On success:
        failedLoginAttempts.delete(`${ip}:${email}`)
    } catch (error) {
        // On failure:
        const key = `${ip}:${email}`
        const attempts = failedLoginAttempts.get(key) || 0
        failedLoginAttempts.set(key, attempts + 1)
        
        if (attempts >= 5) {
            // Log suspicious activity
            logSecurityEvent('suspicious_login_attempts', {
                ip,
                email,
                attempts: attempts + 1
            })
            
            // Temporarily block IP
            // Consider adding IP to rate limiter blacklist
        }
    }
})
```

---

### 9. **API Key Rotation**

#### Implement token refresh:

```javascript
// Add refresh token endpoint
app.post("/api/auth/refresh", async (req, res) => {
    const refreshToken = req.cookies.lumra_refresh_token || req.headers['x-refresh-token']
    
    if (!refreshToken) {
        return res.status(401).json({ error: "Refresh token required" })
    }
    
    try {
        const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET)
        
        // Generate new access token
        const newToken = jwt.sign(
            { email: decoded.email, name: decoded.name },
            JWT_SECRET,
            { expiresIn: '15m' }  // Short-lived access token
        )
        
        res.json({ token: newToken })
    } catch (error) {
        res.status(401).json({ error: "Invalid refresh token" })
    }
})
```

---

### 10. **Environment Variable Security**

#### Use dotenv-safe:
```bash
npm install dotenv-safe
```

```javascript
import dotenvSafe from 'dotenv-safe'

dotenvSafe.config({
    allowEmptyValues: false,  // Require all variables
    example: './env.example'
})
```

#### Secrets Management:
- **Never commit `.env` files**
- Use environment variable management tools:
  - **Vercel**: Built-in environment variables
  - **Railway**: Environment variables dashboard
  - **AWS Secrets Manager**: For production
  - **HashiCorp Vault**: Enterprise solution

---

### 11. **SSL/TLS Certificate Management**

#### Use HTTPS in Production:
```javascript
// Force HTTPS
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production' && !req.secure) {
        return res.redirect(`https://${req.headers.host}${req.url}`)
    }
    next()
})
```

#### Certificate Management:
- **Let's Encrypt** (Free SSL certificates)
- **Auto-renewal**: Use certbot or your hosting provider
- **HSTS Headers**: Already configured in Helmet

---

### 12. **Firewall & Network Security**

#### Cloud Firewall Rules:
- Restrict access to backend port (5050)
- Only allow specific IPs for admin access
- Use VPN for developer access

#### DDoS Protection:
- **Cloudflare** (Free tier available)
  - DDoS protection
  - Rate limiting
  - Bot detection
  - CDN and caching

- **AWS WAF** (if using AWS)
- **CloudFront** (AWS CDN with DDoS protection)

---

### 13. **Container Security** (If Using Docker)

```dockerfile
# Use minimal base images
FROM node:18-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application
COPY --chown=nodejs:nodejs . .

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 5050

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node healthcheck.js

CMD ["node", "server.js"]
```

#### Docker Security Best Practices:
- Scan images for vulnerabilities
- Use minimal base images
- Run as non-root user
- Keep images updated
- Use secrets management (Docker secrets)

---

### 14. **Database Security** (When You Add a Database)

#### Recommended:
- **PostgreSQL** with encryption at rest
- **MongoDB Atlas** (managed, encrypted)
- Use connection pooling
- Enable SSL/TLS for connections
- Regular backups with encryption
- Access control and authentication

```javascript
// Example: MongoDB with encryption
import mongoose from 'mongoose'

const mongoOptions = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    ssl: true,  // Enable SSL
    sslValidate: true,
    authSource: 'admin'
}

mongoose.connect(MONGO_URI, mongoOptions)
```

---

### 15. **API Security Headers**

#### Additional Headers:
```javascript
app.use((req, res, next) => {
    // X-Content-Type-Options
    res.setHeader('X-Content-Type-Options', 'nosniff')
    
    // X-Frame-Options
    res.setHeader('X-Frame-Options', 'DENY')
    
    // Referrer-Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
    
    // Permissions-Policy
    res.setHeader('Permissions-Policy', 
        'geolocation=(), microphone=(), camera=()'
    )
    
    // Remove server information
    res.removeHeader('X-Powered-By')
    
    next()
})
```

---

### 16. **Email Security** (For Password Resets)

#### If adding email functionality:
- Use verified email services (SendGrid, AWS SES)
- Implement email verification
- Rate limit email sending
- Use SPF, DKIM, DMARC records
- Avoid sending sensitive data via email

---

### 17. **File Upload Security** (If Adding File Uploads)

```javascript
const multer = require('multer')
const path = require('path')

const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => {
        // Generate secure filename
        const ext = path.extname(file.originalname)
        const name = crypto.randomBytes(16).toString('hex')
        cb(null, name + ext)
    }
})

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
    fileFilter: (req, file, cb) => {
        // Whitelist allowed file types
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif']
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true)
        } else {
            cb(new Error('Invalid file type'))
        }
    }
})

// Virus scanning (optional but recommended)
// Use ClamAV or commercial solutions
```

---

### 18. **Security Monitoring & Alerts**

#### Tools:
- **Sentry** (Error tracking)
  - Security alerts
  - Performance monitoring
  - Release tracking

- **LogRocket** (Session replay)
  - Debug security issues
  - User behavior analysis

- **DataDog** or **New Relic** (APM)
  - Performance monitoring
  - Security metrics

#### Custom Monitoring:
```javascript
// Track security metrics
const securityMetrics = {
    failedLogins: 0,
    rateLimitHits: 0,
    suspiciousActivity: 0
}

// Alert on anomalies
function checkSecurityMetrics() {
    if (securityMetrics.failedLogins > 100) {
        // Send alert to admin
        sendSecurityAlert('High failed login attempts detected')
    }
}
```

---

### 19. **Penetration Testing**

#### Tools:
- **OWASP ZAP** (Free)
  - Automated security testing
  - Vulnerability scanning

- **Burp Suite** (Free Community Edition)
  - Web vulnerability scanner
  - Manual testing tools

- **Nmap** (Network scanning)
  - Port scanning
  - Service detection

#### Regular Testing:
- Schedule monthly security scans
- Test after major updates
- Use automated tools in CI/CD

---

### 20. **Backup & Disaster Recovery**

#### Implementation:
```javascript
// Automated backups
const cron = require('node-cron')

// Daily backup at 2 AM
cron.schedule('0 2 * * *', () => {
    backupDatabase()
    backupUserFiles()
    // Store in encrypted storage
})
```

#### Backup Security:
- Encrypt backups
- Store off-site
- Test restore procedures
- Version control backups

---

### 21. **Code Security Best Practices**

#### Use ESLint Security Plugins:
```bash
npm install -D eslint-plugin-security
```

```json
// .eslintrc.json
{
  "extends": ["plugin:security/recommended"],
  "plugins": ["security"],
  "rules": {
    "security/detect-object-injection": "error",
    "security/detect-non-literal-fs-filename": "warn",
    "security/detect-eval-with-expression": "error"
  }
}
```

---

### 22. **CI/CD Security**

#### GitHub Actions Security:
```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm ci
      - run: npm audit --audit-level=high
      - run: npm run lint
```

---

### 23. **Regular Security Audits**

#### Checklist:
- [ ] Monthly dependency updates
- [ ] Quarterly security audits
- [ ] Annual penetration testing
- [ ] Review access logs weekly
- [ ] Update security patches immediately
- [ ] Rotate secrets quarterly
- [ ] Review and update rate limits
- [ ] Check for exposed secrets (GitHub secrets scanner)

---

## 🚨 Immediate Actions You Can Take

### Priority 1 (Do Now):
1. ✅ Run `npm audit` and fix vulnerabilities
2. ✅ Set up dependency monitoring (Snyk or Dependabot)
3. ✅ Enhance CSP headers (remove unsafe-inline)
4. ✅ Add request logging for security events
5. ✅ Implement failed login attempt tracking

### Priority 2 (This Week):
1. Add express-validator for better validation
2. Set up winston logging
3. Implement refresh tokens
4. Add suspicious activity detection
5. Set up error tracking (Sentry)

### Priority 3 (This Month):
1. Set up Cloudflare or similar DDoS protection
2. Implement automated security scanning
3. Add email verification if using email
4. Set up automated backups
5. Create security incident response plan

---

## 📚 Additional Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Node.js Security Best Practices**: https://nodejs.org/en/docs/guides/security/
- **Express Security Best Practices**: https://expressjs.com/en/advanced/best-practice-security.html
- **Mozilla Web Security Guidelines**: https://infosec.mozilla.org/guidelines/web_security

---

## 🔐 Security Checklist

Use this checklist to ensure your application is secure:

- [ ] All dependencies updated and audited
- [ ] Strong secrets and passwords
- [ ] HTTPS enabled in production
- [ ] Security headers configured
- [ ] Rate limiting implemented
- [ ] Input validation and sanitization
- [ ] Authentication and authorization
- [ ] Secure cookie configuration
- [ ] Error handling (no stack traces in production)
- [ ] Logging and monitoring
- [ ] Regular backups
- [ ] Security incident response plan

---

**Remember**: Security is an ongoing process, not a one-time setup. Regularly review and update your security measures.



