# Quick Security Implementation Guide

This guide provides step-by-step instructions to implement the most critical security measures.

## 🚀 Quick Start: Top 5 Security Measures

### 1. Dependency Vulnerability Scanning

```bash
# Install Snyk CLI (if not already installed)
npm install -g snyk

# Authenticate
snyk auth

# Test your project
snyk test

# Monitor continuously
snyk monitor

# Add to package.json scripts
```

Add to `lumra/package.json`:
```json
{
  "scripts": {
    "security:audit": "npm audit",
    "security:fix": "npm audit fix",
    "security:test": "snyk test || true"
  }
}
```

---

### 2. Enhanced Logging (Quick Implementation)

```bash
npm install winston
```

Add to `lumra/server.js`:
```javascript
import winston from 'winston'

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.simple()
        }),
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error' 
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log' 
        })
    ],
})

// Log security events
function logSecurityEvent(type, details, req) {
    logger.warn('Security Event', {
        type,
        ...details,
        ip: req?.ip,
        userAgent: req?.headers['user-agent'],
        timestamp: new Date().toISOString()
    })
}

// Use in login endpoint
app.post("/api/auth/login", authLimiter, async (req, res) => {
    try {
        // ... login logic
    } catch (error) {
        logSecurityEvent('failed_login', {
            email: req.body.email,
            error: error.message
        }, req)
        // ... error handling
    }
})
```

Create `logs/` directory:
```bash
mkdir logs
echo "logs/*" >> .gitignore
```

---

### 3. Failed Login Attempt Tracking

Add to `lumra/server.js`:
```javascript
// Track failed login attempts (store in Redis for production)
const failedLoginAttempts = new Map()
const MAX_ATTEMPTS = 5
const BLOCK_DURATION = 15 * 60 * 1000 // 15 minutes

function isBlocked(ip, email) {
    const key = `${ip}:${email}`
    const attempts = failedLoginAttempts.get(key)
    
    if (attempts && attempts.count >= MAX_ATTEMPTS) {
        const timeSinceFirst = Date.now() - attempts.firstAttempt
        if (timeSinceFirst < BLOCK_DURATION) {
            return true
        } else {
            // Reset after block duration
            failedLoginAttempts.delete(key)
            return false
        }
    }
    return false
}

function recordFailedAttempt(ip, email) {
    const key = `${ip}:${email}`
    const existing = failedLoginAttempts.get(key) || { count: 0, firstAttempt: Date.now() }
    
    failedLoginAttempts.set(key, {
        count: existing.count + 1,
        firstAttempt: existing.firstAttempt
    })
    
    // Log if approaching limit
    if (existing.count + 1 >= MAX_ATTEMPTS - 1) {
        logSecurityEvent('suspicious_login_attempts', {
            ip,
            email,
            attempts: existing.count + 1
        })
    }
}

// Update login endpoint
app.post("/api/auth/login", authLimiter, async (req, res) => {
    const ip = req.ip
    const email = req.body.email?.toLowerCase().trim()
    
    // Check if blocked
    if (isBlocked(ip, email)) {
        return res.status(429).json({ 
            error: "Too many failed login attempts. Please try again in 15 minutes." 
        })
    }
    
    try {
        // ... existing login logic
        
        // On success, clear attempts
        failedLoginAttempts.delete(`${ip}:${email}`)
        
    } catch (error) {
        // On failure
        recordFailedAttempt(ip, email)
        // ... error handling
    }
})
```

---

### 4. Request Validation with express-validator

```bash
npm install express-validator
```

Update `lumra/server.js`:
```javascript
import { body, validationResult } from 'express-validator'

// Validation middleware
const validateLogin = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Invalid email address'),
    body('password')
        .isLength({ min: 8, max: 128 })
        .withMessage('Password must be 8-128 characters')
]

// Apply to login endpoint
app.post("/api/auth/login", 
    authLimiter,
    validateLogin,
    async (req, res) => {
        // Check validation errors
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

### 5. Enhanced CSP Headers

Update Helmet configuration in `lumra/server.js`:
```javascript
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"], // Remove 'unsafe-inline' in production
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: [
                "'self'", 
                "https://api.openai.com", 
                "https://api.anthropic.com"
            ],
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
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    permittedCrossDomainPolicies: false,
}))
```

---

## 📋 Security Monitoring Script

Create `lumra/scripts/security-check.js`:
```javascript
import { execSync } from 'child_process'
import fs from 'fs'

console.log('🔒 Running Security Checks...\n')

// 1. Check npm audit
console.log('1. Checking npm audit...')
try {
    const audit = execSync('npm audit --json', { encoding: 'utf8' })
    const auditData = JSON.parse(audit)
    if (auditData.vulnerabilities?.total > 0) {
        console.log(`⚠️  Found ${auditData.vulnerabilities.total} vulnerabilities`)
    } else {
        console.log('✅ No vulnerabilities found')
    }
} catch (error) {
    console.log('❌ Error running npm audit')
}

// 2. Check for exposed secrets
console.log('\n2. Checking for exposed secrets...')
const files = ['server.js', '.env']
const secretPatterns = [
    /password\s*=\s*['"]\w+['"]/i,
    /secret\s*=\s*['"]\w+['"]/i,
    /api[_-]?key\s*=\s*['"][\w-]+['"]/i,
]

files.forEach(file => {
    if (fs.existsSync(file)) {
        const content = fs.readFileSync(file, 'utf8')
        secretPatterns.forEach(pattern => {
            if (pattern.test(content)) {
                console.log(`⚠️  Potential secret found in ${file}`)
            }
        })
    }
})

console.log('\n✅ Security check complete')
```

Add to `package.json`:
```json
{
  "scripts": {
    "security:check": "node scripts/security-check.js"
  }
}
```

---

## 🔐 Recommended Third-Party Services

### Free Tier Available:
1. **Cloudflare** - DDoS protection, CDN, WAF
2. **Sentry** - Error tracking and security alerts
3. **Snyk** - Dependency vulnerability scanning
4. **Let's Encrypt** - Free SSL certificates

### Paid (Worth Considering):
1. **Datadog** or **New Relic** - APM and security monitoring
2. **AWS WAF** - Web application firewall
3. **Auth0** - Advanced authentication (if you need more features)

---

## 🎯 Priority Implementation Order

1. **Week 1**: Dependency scanning + logging
2. **Week 2**: Failed login tracking + express-validator
3. **Week 3**: Enhanced CSP + security monitoring script
4. **Week 4**: Set up Cloudflare or similar DDoS protection

---

## 📞 Security Incident Response

Create a response plan:

1. **Isolate**: Immediately block suspicious IPs
2. **Investigate**: Check logs for the attack pattern
3. **Fix**: Patch vulnerabilities or update security measures
4. **Notify**: Inform affected users if data was compromised
5. **Document**: Record the incident for future reference

---

**Remember**: Implement these gradually. Don't try to do everything at once. Focus on the most critical items first.



