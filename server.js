import express from "express"
import cors from "cors"
import dotenv from "dotenv"
import OpenAI from "openai"
import Anthropic from "@anthropic-ai/sdk"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import session from "express-session"
import passport from "passport"
import { Strategy as GoogleStrategy } from "passport-google-oauth20"
import helmet from "helmet"
import rateLimit from "express-rate-limit"
import cookieParser from "cookie-parser"
import { readFileSync, writeFileSync, existsSync, appendFileSync, statSync, mkdirSync } from "fs"
import { fileURLToPath } from "url"
import { dirname, join } from "path"
import multer from "multer"
import { Resend } from "resend"
import { initializeRAG, processAndStoreDocument, retrieveRelevantDocuments, formatRetrievedContext, removeDocument, isRAGAvailable, createEmbedding } from "./rag.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

dotenv.config()

// Log File Configuration
const LOG_FILE = join(__dirname, "server.log")

// Conversations Storage File
const CONVERSATIONS_FILE = join(__dirname, "conversations.json")

// Calendar Storage File
const CALENDAR_FILE = join(__dirname, "calendar.json")

// Load calendar data
function loadCalendar() {
    if (existsSync(CALENDAR_FILE)) {
        try {
            const data = readFileSync(CALENDAR_FILE, "utf-8")
            return JSON.parse(data)
        } catch (error) {
            log(`[Calendar] Error loading calendar: ${error.message}`, "error")
            return {}
        }
    }
    return {}
}

// Save calendar data
function saveCalendar(data) {
    try {
        writeFileSync(CALENDAR_FILE, JSON.stringify(data, null, 2), "utf-8")
        return true
    } catch (error) {
        log(`[Calendar] Error saving calendar: ${error.message}`, "error")
        return false
    }
}

// Get user's calendar events
function getUserCalendar(userEmail) {
    const calendarData = loadCalendar()
    return calendarData[userEmail] || { events: [], dueDates: [], classes: [] }
}

// Save user's calendar events
function saveUserCalendar(userEmail, calendarData) {
    const allCalendars = loadCalendar()
    allCalendars[userEmail] = calendarData
    saveCalendar(allCalendars)
}

// Enhanced logging function that writes to both console and file
function log(message, type = 'log') {
    const timestamp = new Date().toISOString()
    const logMessage = `[${timestamp}] ${message}`
    
    // Always log to console
    if (type === 'error') {
        console.error(logMessage)
    } else {
        console.log(logMessage)
    }
    
    // Also write to log file
    try {
        appendFileSync(LOG_FILE, logMessage + '\n', 'utf8')
    } catch (error) {
        // If file write fails, just continue (don't break the app)
        console.error('Failed to write to log file:', error.message)
    }
}

// Maintenance Mode Configuration
const MAINTENANCE_FILE = join(__dirname, "maintenance.json")

function loadMaintenanceMode() {
    if (existsSync(MAINTENANCE_FILE)) {
        try {
            const data = readFileSync(MAINTENANCE_FILE, "utf-8")
            const parsed = JSON.parse(data)
            return {
                enabled: Boolean(parsed.enabled),
                message: parsed.message || "AI services are currently under maintenance. Please try again later.",
                updatedAt: parsed.updatedAt || new Date().toISOString()
            }
        } catch (error) {
            console.error("Error loading maintenance mode:", error)
            return { enabled: false, message: "", updatedAt: null }
        }
    }
    return { enabled: false, message: "", updatedAt: null }
}

function saveMaintenanceMode(enabled, message = "") {
    try {
        const data = {
            enabled: Boolean(enabled),
            message: message || "AI services are currently under maintenance. Please try again later.",
            updatedAt: new Date().toISOString()
        }
        console.log(`[Maintenance Mode] Saving to ${MAINTENANCE_FILE}:`, data)
        writeFileSync(MAINTENANCE_FILE, JSON.stringify(data, null, 2), "utf-8")
        console.log(`[Maintenance Mode] ✅ File saved successfully`)
        
        // Verify file was created
        if (existsSync(MAINTENANCE_FILE)) {
            const verify = readFileSync(MAINTENANCE_FILE, "utf-8")
            console.log(`[Maintenance Mode] ✅ Verified file exists, content:`, verify)
        } else {
            console.error(`[Maintenance Mode] ❌ File does not exist after save!`)
        }
        
        return data
    } catch (error) {
        console.error("[Maintenance Mode] ❌ Error saving maintenance mode:", error)
        console.error("[Maintenance Mode] Error stack:", error.stack)
        return null
    }
}

// Email configuration function (runs asynchronously, doesn't block)
async function sendDemoKeyRequestEmail(name, email) {
    try {
        // Always log to file first (fast and reliable)
        const emailLogFile = join(__dirname, "demo_key_requests.log")
        const logEntry = `[${new Date().toISOString()}] Name: ${name}, Email: ${email}\n`
        appendFileSync(emailLogFile, logEntry, "utf-8")
        log(`[Email] Request logged to file: ${name} (${email})`)

        // Check for Resend API key (preferred) or fallback to Gmail SMTP
        const resendApiKey = process.env.RESEND_API_KEY
        const fromEmail = process.env.RESEND_FROM_EMAIL || 'onboarding@resend.dev'
        const toEmail = process.env.RESEND_TO_EMAIL || 'darshvekaria1@gmail.com'

        if (resendApiKey) {
            // Use Resend API (much more reliable)
            log(`[Email] Using Resend API for email delivery...`)
            const resend = new Resend(resendApiKey)

            const emailPromise = resend.emails.send({
                from: `Lumra AI <${fromEmail}>`,
                to: [toEmail],
                replyTo: email,
                subject: `🔑 New Demo Key Request - ${name}`,
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #333; border-bottom: 2px solid #6366f1; padding-bottom: 10px;">New Demo Key Request</h2>
                        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                            <p style="margin: 10px 0;"><strong>Name:</strong> ${name}</p>
                            <p style="margin: 10px 0;"><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
                            <p style="margin: 10px 0;"><strong>Requested At:</strong> ${new Date().toLocaleString()}</p>
                            <p style="margin: 10px 0;"><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
                        </div>
                        <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                        <p style="color: #666;">Please generate a demo key for this user and send it to: <strong>${email}</strong></p>
                        <p style="color: #999; font-size: 12px; margin-top: 30px;">This is an automated notification from Lumra AI.</p>
                    </div>
                `,
                text: `
New Demo Key Request

Name: ${name}
Email: ${email}
Requested At: ${new Date().toLocaleString()}
Timestamp: ${new Date().toISOString()}

Please generate a demo key for this user and send it to: ${email}
                `
            })

            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Resend API timeout')), 10000)
            )

            const info = await Promise.race([emailPromise, timeoutPromise])
            log(`[Email] ✅ Email sent successfully via Resend! Message ID: ${info.data?.id || 'unknown'}`)
            log(`[Email] ✅ Email sent to: ${toEmail}`)
            return info
        } else {
            // Fallback: Try Gmail SMTP (may timeout, but request is still saved)
            log(`[Email] ⚠️ RESEND_API_KEY not set. Using file logging only.`)
            log(`[Email] To enable email: Get free API key from https://resend.com and set RESEND_API_KEY in Render`)
            return { messageId: 'logged-only', error: 'Resend API key not configured' }
        }
    } catch (error) {
        log(`[Email] ❌ Error sending email: ${error.message}`, "error")
        log(`[Email] ❌ Error stack: ${error.stack}`, "error")
        // Request is already saved to file, so this is fine
        return { messageId: 'failed', error: error.message }
    }
}

// Email notification for contact form submissions
async function sendContactEmailNotification(email, message) {
    try {
        const resendApiKey = process.env.RESEND_API_KEY
        const fromEmail = process.env.RESEND_FROM_EMAIL || 'onboarding@resend.dev'
        const toEmail = process.env.RESEND_TO_EMAIL || 'darshvekaria1@gmail.com'

        if (!resendApiKey) {
            log(`[Contact Email] RESEND_API_KEY not configured. Contact saved to file only.`)
            return { messageId: 'logged-only', error: 'Resend API key not configured' }
        }

        const resend = new Resend(resendApiKey)

        const emailPromise = resend.emails.send({
            from: `Lumra AI <${fromEmail}>`,
            to: [toEmail],
            replyTo: email,
            subject: `📧 New Contact Form Submission - ${email}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #333; border-bottom: 2px solid #6366f1; padding-bottom: 10px;">New Contact Form Submission</h2>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <p style="margin: 10px 0;"><strong>From:</strong> <a href="mailto:${email}">${email}</a></p>
                        <p style="margin: 10px 0;"><strong>Submitted At:</strong> ${new Date().toLocaleString()}</p>
                        <p style="margin: 10px 0;"><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
                    </div>
                    <div style="background: #ffffff; padding: 20px; border-radius: 8px; border: 1px solid #ddd; margin: 20px 0;">
                        <h3 style="color: #333; margin-top: 0;">Message:</h3>
                        <p style="color: #666; white-space: pre-wrap; line-height: 1.6;">${message.replace(/\n/g, '<br>')}</p>
                    </div>
                    <p style="color: #999; font-size: 12px; margin-top: 30px;">This is an automated notification from Lumra AI contact form.</p>
                </div>
            `,
            text: `
New Contact Form Submission

From: ${email}
Submitted At: ${new Date().toLocaleString()}
Timestamp: ${new Date().toISOString()}

Message:
${message}
            `
        })

        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Resend API timeout')), 10000)
        )

        const info = await Promise.race([emailPromise, timeoutPromise])
        log(`[Contact Email] ✅ Email sent successfully via Resend! Message ID: ${info.data?.id || 'unknown'}`)
        return info
    } catch (error) {
        log(`[Contact Email] ❌ Error sending email: ${error.message}`, "error")
        return { messageId: 'failed', error: error.message }
    }
}

const app = express()
const port = Number(process.env.PORT) || 5050

// Trust proxy - required for Render and other reverse proxy services
app.set('trust proxy', true)

const allowedOrigins = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(",").map((origin) => origin.trim()).filter(Boolean)
    : ["http://localhost:5173", "http://localhost:5174", "http://localhost:3000", "http://127.0.0.1:5173", "http://127.0.0.1:5174"]

const corsOptions = {
    origin(origin, callback) {
        // Allow requests with no origin (like same-origin requests, mobile apps, curl, etc.)
        if (!origin) {
            return callback(null, true)
        }
        if (allowedOrigins.includes(origin) || allowedOrigins.includes("*")) {
            callback(null, true)
        } else {
            callback(new Error("Not allowed by CORS"))
        }
    },
    credentials: true,
}

// JWT secret (define early for session config)
const JWT_SECRET = process.env.JWT_SECRET || "lumra-secret-key-change-in-production"
const JWT_EXPIRES_IN = "7d"

// Security headers with Helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    crossOriginEmbedderPolicy: false, // Allow OAuth redirects
}))

// Rate limiting for API endpoints
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: "Too many requests from this IP, please try again later.",
    standardHeaders: true,
    legacyHeaders: false,
})

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit auth endpoints to 10 requests per 15 minutes
    message: "Too many authentication attempts, please try again later.",
    skipSuccessfulRequests: true,
})

const aiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 20, // Limit AI requests to 20 per minute
    message: "Too many AI requests, please slow down.",
})

// Apply CORS only to API routes, not to HTML pages (login, status, analytics)
app.use((req, res, next) => {
    // Skip CORS for HTML pages (same-origin requests)
    if (req.path === '/login' || req.path === '/' || req.path === '/analytics' || req.path === '/logout') {
        return next()
    }
    // Apply CORS to API routes
    cors(corsOptions)(req, res, next)
})

// Cookie parser for secure cookie handling
app.use(cookieParser())

app.use(express.json({ limit: "10mb" }))
app.use(express.urlencoded({ extended: true, limit: "10mb" }))
app.use(express.urlencoded({ extended: true, limit: "1mb" })) // For form submissions

// Input sanitization helper function
function sanitizeInput(input) {
    if (typeof input !== 'string') return input
    // Remove potentially dangerous characters
    return input
        .replace(/[<>]/g, '') // Remove < and > to prevent XSS
        .trim()
        .substring(0, 1000) // Limit length
}

// Enhanced validation functions with sanitization
function isValidEmail(email) {
    if (typeof email !== 'string') return false
    const sanitized = sanitizeInput(email)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(sanitized) && sanitized.length <= 254
}

function isValidPassword(password) {
    if (typeof password !== 'string') {
        return { valid: false, error: "Password must be a string" }
    }
    if (password.length < 8) {
        return { valid: false, error: "Password must be at least 8 characters long" }
    }
    if (password.length > 128) {
        return { valid: false, error: "Password must be less than 128 characters" }
    }
    // Enhanced password requirements
    if (!/[a-zA-Z]/.test(password)) {
        return { valid: false, error: "Password must contain at least one letter" }
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, error: "Password must contain at least one number" }
    }
    // Optional: Require uppercase and lowercase
    // if (!/[A-Z]/.test(password)) {
    //     return { valid: false, error: "Password must contain at least one uppercase letter" }
    // }
    // if (!/[a-z]/.test(password)) {
    //     return { valid: false, error: "Password must contain at least one lowercase letter" }
    // }
    return { valid: true }
}

// Request logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString()
    console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`)
    next()
})

// Session configuration for OAuth and developer auth with enhanced security
app.use(
    session({
        secret: process.env.SESSION_SECRET || JWT_SECRET,
        resave: false,
        saveUninitialized: false,
        name: 'lumra.sid', // Custom session name (not default 'connect.sid')
        cookie: {
            secure: process.env.NODE_ENV === "production", // HTTPS only in production
            httpOnly: true, // Prevents XSS attacks - JavaScript cannot access cookie
            sameSite: 'strict', // CSRF protection - only send cookie with same-site requests
            maxAge: 24 * 60 * 60 * 1000, // 24 hours
            domain: process.env.COOKIE_DOMAIN || undefined, // Restrict to specific domain
            path: '/', // Cookie path
        },
        // Additional session security
        rolling: true, // Reset expiration on each request
        proxy: process.env.NODE_ENV === "production", // Trust proxy in production
    })
)

// Developer authentication middleware
function requireDeveloperAuth(req, res, next) {
    if (req.session && req.session.developerAuthenticated) {
        return next()
    }
    // Redirect to login if not authenticated, preserving the intended destination
    const returnUrl = req.originalUrl !== '/login' ? `?returnUrl=${encodeURIComponent(req.originalUrl)}` : ''
    res.redirect(`/login${returnUrl}`)
}

// Developer login page
app.get("/login", (req, res) => {
    if (req.session && req.session.developerAuthenticated) {
        // Redirect to intended destination or default to status page
        const returnUrl = req.query.returnUrl || '/'
        return res.redirect(returnUrl)
    }
    
    const error = req.query.error || ''
    const returnUrl = req.query.returnUrl || '/'
    
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚠️ Developer Access - Lumra Backend (RESTRICTED)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        body::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: repeating-linear-gradient(
                45deg,
                transparent,
                transparent 10px,
                rgba(239, 68, 68, 0.05) 10px,
                rgba(239, 68, 68, 0.05) 20px
            );
            pointer-events: none;
        }
        .container {
            background: #1e293b;
            border: 2px solid #ef4444;
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.8), 0 0 30px rgba(239, 68, 68, 0.3);
            max-width: 500px;
            width: 100%;
            position: relative;
            z-index: 1;
        }
        .warning-banner {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            padding: 16px;
            border-radius: 12px;
            margin-bottom: 24px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.5);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { box-shadow: 0 4px 15px rgba(239, 68, 68, 0.5); }
            50% { box-shadow: 0 4px 25px rgba(239, 68, 68, 0.8); }
        }
        .warning-banner h2 {
            font-size: 1.1rem;
            margin-bottom: 8px;
            font-weight: 700;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .warning-banner p {
            font-size: 0.85rem;
            opacity: 0.95;
            line-height: 1.5;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #fbbf24;
            font-size: 2rem;
            margin-bottom: 8px;
            text-shadow: 0 0 20px rgba(251, 191, 36, 0.5);
        }
        .logo p {
            color: #94a3b8;
            font-size: 0.9rem;
        }
        .caution-box {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid #ef4444;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 24px;
            color: #fca5a5;
            font-size: 0.85rem;
            line-height: 1.6;
        }
        .caution-box strong {
            color: #fbbf24;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #e2e8f0;
            font-weight: 600;
            margin-bottom: 8px;
            font-size: 0.9rem;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            background: #0f172a;
            border: 2px solid #334155;
            border-radius: 8px;
            font-size: 1rem;
            color: #e2e8f0;
            transition: all 0.2s;
        }
        input::placeholder {
            color: #64748b;
        }
        input:focus {
            outline: none;
            border-color: #ef4444;
            box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.2);
        }
        .error {
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid #ef4444;
            color: #fca5a5;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.9rem;
            display: ${error ? 'block' : 'none'};
        }
        .submit-btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.4);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.6);
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
        }
        .submit-btn:active {
            transform: translateY(0);
        }
        .info {
            margin-top: 24px;
            padding: 16px;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid #334155;
            border-radius: 8px;
            font-size: 0.85rem;
            color: #94a3b8;
            text-align: center;
            line-height: 1.6;
        }
        .info strong {
            color: #fbbf24;
        }
        .restricted-badge {
            display: inline-block;
            background: #ef4444;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 700;
            margin-top: 8px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning-banner">
            <h2>⚠️ RESTRICTED ACCESS ZONE ⚠️</h2>
            <p>This area is exclusively for authorized developers only.<br>Unauthorized access is prohibited and may be logged.</p>
        </div>
        
        <div class="logo">
            <h1>🔐 Developer Access</h1>
            <p>Lumra Backend Server - Port 5050</p>
        </div>
        
        <div class="caution-box">
            <strong>⚠️ CAUTION:</strong><br>
            • This is a <strong>RESTRICTED PAGE</strong> for developers only<br>
            • Only authorized personnel should proceed<br>
            • All access attempts are monitored and logged<br>
            • Unauthorized access is strictly prohibited
        </div>
        
        ${error ? `<div class="error">⚠️ ${error}</div>` : ''}
        
        <form method="POST" action="/login">
            <input type="hidden" name="returnUrl" value="${returnUrl}">
            <div class="form-group">
                <label for="username">Developer Username</label>
                <input type="text" id="username" name="username" required autofocus placeholder="Enter authorized developer username" value="${error ? '' : ''}">
            </div>
            
            <div class="form-group">
                <label for="password">Developer Password</label>
                <input type="password" id="password" name="password" required placeholder="Enter authorized developer password">
            </div>
            
            <button type="submit" class="submit-btn">⚠️ Sign In to Backend</button>
        </form>
        
        <div class="info">
            <strong>🔒 RESTRICTED AREA</strong><br>
            Access to: Status Dashboard, Analytics & System Logs<br>
            <span class="restricted-badge">Developers Only</span>
        </div>
    </div>
</body>
</html>
    `)
})

// Developer login handler
app.post("/login", (req, res) => {
    const { username, password, returnUrl } = req.body || {}
    
    // Strict credentials - only allow exact match
    const DEV_USERNAME = "developer"
    const DEV_PASSWORD = "lumra2024"
    
    // Validate input
    if (!username || !password) {
        const redirectUrl = returnUrl ? `/login?error=${encodeURIComponent('Username and password are required')}&returnUrl=${encodeURIComponent(returnUrl)}` : '/login?error=' + encodeURIComponent('Username and password are required')
        return res.redirect(redirectUrl)
    }
    
    // Trim and validate exact match (case-sensitive)
    const trimmedUsername = username.trim()
    const trimmedPassword = password.trim()
    
    // Strict validation - only these exact credentials work
    if (trimmedUsername === DEV_USERNAME && trimmedPassword === DEV_PASSWORD) {
        req.session.developerAuthenticated = true
        req.session.developerUsername = trimmedUsername
        console.log(`[Developer Auth] Successful login from IP: ${req.ip}`)
        // Redirect to intended destination or default to status page
        const destination = returnUrl && returnUrl !== '/login' ? returnUrl : '/'
        return res.redirect(destination)
    } else {
        console.log(`[Developer Auth] Failed login attempt - Username: "${trimmedUsername}" from IP: ${req.ip}`)
        const redirectUrl = returnUrl ? `/login?error=${encodeURIComponent('Invalid username or password. Access denied.')}&returnUrl=${encodeURIComponent(returnUrl)}` : '/login?error=' + encodeURIComponent('Invalid username or password. Access denied.')
        return res.redirect(redirectUrl)
    }
})

// Developer logout with cookie clearing
app.get("/logout", (req, res) => {
    // Clear all authentication cookies
    res.clearCookie('lumra_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: 'strict',
        path: '/',
    })
    res.clearCookie('lumra.sid', {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: 'strict',
        path: '/',
    })
    
    // Destroy session
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err)
        }
        res.redirect('/login')
    })
})

// Initialize Passport
app.use(passport.initialize())
app.use(passport.session())

// User storage (in-memory, persists to JSON file)
const USERS_FILE = join(__dirname, "users.json")
let users = new Map()

// Response Cache for Quick Mode optimizations
const responseCache = new Map()
const CACHE_TTL = 24 * 60 * 60 * 1000 // 24 hours in milliseconds

// Helper function to generate cache key from prompt and history
function generateCacheKey(prompt, conversationHistory = [], system = null) {
    const historyHash = conversationHistory
        ? conversationHistory.slice(-3).map(m => `${m.role}:${m.content.substring(0, 100)}`).join('|')
        : ''
    const systemHash = system ? system.substring(0, 50) : ''
    return `${prompt.substring(0, 200)}|${historyHash}|${systemHash}`.toLowerCase().replace(/\s+/g, ' ')
}

// Helper function to check cache
function getCachedResponse(cacheKey) {
    const cached = responseCache.get(cacheKey)
    if (!cached) return null
    
    const now = Date.now()
    if (now - cached.timestamp > CACHE_TTL) {
        responseCache.delete(cacheKey)
        return null
    }
    
    return cached.response
}

// Helper function to set cache
function setCachedResponse(cacheKey, response) {
    responseCache.set(cacheKey, {
        response,
        timestamp: Date.now()
    })
    
    // Limit cache size to 1000 entries (prevent memory issues)
    if (responseCache.size > 1000) {
        const firstKey = responseCache.keys().next().value
        responseCache.delete(firstKey)
    }
}

// Helper function to calculate similarity between two responses (0-1)
function calculateSimilarity(str1, str2) {
    if (!str1 || !str2) return 0
    
    // Normalize strings
    const normalize = (s) => s.toLowerCase().replace(/\s+/g, ' ').trim()
    const n1 = normalize(str1)
    const n2 = normalize(str2)
    
    // If identical after normalization
    if (n1 === n2) return 1.0
    
    // Calculate word overlap
    const words1 = new Set(n1.split(/\s+/))
    const words2 = new Set(n2.split(/\s+/))
    
    const intersection = new Set([...words1].filter(x => words2.has(x)))
    const union = new Set([...words1, ...words2])
    
    // Jaccard similarity
    const jaccard = intersection.size / union.size
    
    // Also check if one is substring of another (for shorter responses)
    const substringMatch = n1.includes(n2) || n2.includes(n1)
    const substringBonus = substringMatch ? 0.2 : 0
    
    return Math.min(1.0, jaccard + substringBonus)
}

// Helper function to merge similar responses without API call
function mergeResponsesClientSide(chatgptReply, claudeReply) {
    // If responses are very similar, just combine unique parts
    const similarity = calculateSimilarity(chatgptReply, claudeReply)
    
    if (similarity > 0.85) {
        // Very similar - just return the longer/more detailed one
        return chatgptReply.length > claudeReply.length ? chatgptReply : claudeReply
    }
    
    // Different enough - combine them intelligently
    // Remove duplicate sentences
    const chatgptSentences = chatgptReply.split(/[.!?]\s+/).filter(s => s.trim())
    const claudeSentences = claudeReply.split(/[.!?]\s+/).filter(s => s.trim())
    
    const uniqueSentences = new Set()
    const combined = []
    
    // Add ChatGPT sentences first
    for (const sentence of chatgptSentences) {
        const normalized = sentence.toLowerCase().trim()
        if (!uniqueSentences.has(normalized)) {
            uniqueSentences.add(normalized)
            combined.push(sentence)
        }
    }
    
    // Add Claude sentences that are unique
    for (const sentence of claudeSentences) {
        const normalized = sentence.toLowerCase().trim()
        if (!uniqueSentences.has(normalized)) {
            uniqueSentences.add(normalized)
            combined.push(sentence)
        }
    }
    
    return combined.join('. ').trim()
}

// Load users from file on startup
function loadUsers() {
    if (existsSync(USERS_FILE)) {
        try {
            const data = readFileSync(USERS_FILE, "utf-8")
            const parsed = JSON.parse(data)
            users = new Map(parsed)
        } catch (error) {
            console.error("Error loading users:", error)
            users = new Map()
        }
    }
}

// Save users to file
function saveUsers() {
    try {
        const data = JSON.stringify([...users], null, 2)
        writeFileSync(USERS_FILE, data, "utf-8")
    } catch (error) {
        console.error("Error saving users:", error)
    }
}

// Load users on startup
loadUsers()

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET

// Serialize user for session (OAuth)
passport.serializeUser((user, done) => {
    done(null, user.email)
})

passport.deserializeUser((email, done) => {
    const user = users.get(email)
    done(null, user ? { email: user.email, name: user.name } : null)
})

// Validate Google OAuth Client ID format
function isValidGoogleClientId(clientId) {
    // Google OAuth Client IDs typically end with .apps.googleusercontent.com
    // or are numeric strings
    if (!clientId || typeof clientId !== 'string') return false
    const trimmed = clientId.trim()
    
    // Check if it ends with .apps.googleusercontent.com
    if (trimmed.endsWith('.apps.googleusercontent.com')) return true
    
    // Check if it's a numeric string (some client IDs are just numbers)
    if (/^\d+$/.test(trimmed)) return true
    
    // Check if it contains valid characters (alphanumeric, dots, hyphens)
    if (/^[a-zA-Z0-9._-]+$/.test(trimmed) && trimmed.length > 10) return true
    
    return false
}

// Check for placeholder values
function isPlaceholderValue(value) {
    if (!value) return false
    const lower = value.toLowerCase().trim()
    const placeholders = [
        'your-google-client-id',
        'your-client-secret',
        'your-client-secret-here',
        'your-google-client-id-here',
        'your_google_client_id',
        'your_client_secret',
        'example',
        'placeholder',
        'replace-me',
        'change-me'
    ]
    return placeholders.some(p => lower.includes(p))
}

// Configure Google OAuth Strategy
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
    // Check for placeholder values
    const isClientIdPlaceholder = isPlaceholderValue(GOOGLE_CLIENT_ID)
    const isSecretPlaceholder = isPlaceholderValue(GOOGLE_CLIENT_SECRET)
    
    if (isClientIdPlaceholder || isSecretPlaceholder) {
        console.log(`❌ [Google OAuth] PLACEHOLDER VALUES DETECTED!`)
        console.log(`   ⚠️  Your .env file still contains placeholder values!`)
        if (isClientIdPlaceholder) {
            console.log(`   ❌ GOOGLE_CLIENT_ID is set to placeholder: "${GOOGLE_CLIENT_ID}"`)
            console.log(`   📝 Replace it with your REAL Client ID from Google Console`)
        }
        if (isSecretPlaceholder) {
            console.log(`   ❌ GOOGLE_CLIENT_SECRET is set to placeholder: "${GOOGLE_CLIENT_SECRET.substring(0, 20)}..."`)
            console.log(`   📝 Replace it with your REAL Client Secret from Google Console`)
        }
        console.log(`   🔗 Get credentials from: https://console.cloud.google.com/apis/credentials`)
        console.log(`   ⚠️  Google OAuth will NOT work with placeholder values!`)
    }
    
    // Validate Client ID format
    if (!isValidGoogleClientId(GOOGLE_CLIENT_ID)) {
        console.log(`❌ [Google OAuth] Invalid Client ID format detected!`)
        console.log(`   Client ID provided: "${GOOGLE_CLIENT_ID.substring(0, 50)}"`)
        console.log(`   ⚠️  Client ID should end with .apps.googleusercontent.com`)
        console.log(`   ⚠️  Or be a valid numeric/string identifier from Google Console`)
        console.log(`   🔍 Please verify your GOOGLE_CLIENT_ID in .env file`)
        console.log(`   📝 Get it from: https://console.cloud.google.com/apis/credentials`)
    }
    
    const backendUrl = process.env.BACKEND_URL || `http://localhost:${port}`
    const callbackUrl = process.env.GOOGLE_CALLBACK_URL || `${backendUrl}/api/auth/google/callback`
    
    console.log(`[Google OAuth] Configuration:`)
    console.log(`   Client ID: ${GOOGLE_CLIENT_ID.substring(0, 30)}${GOOGLE_CLIENT_ID.length > 30 ? '...' : ''} (${GOOGLE_CLIENT_ID.length} chars)`)
    console.log(`   Client Secret: ${GOOGLE_CLIENT_SECRET.substring(0, 10)}... (${GOOGLE_CLIENT_SECRET.length} chars)`)
    console.log(`   Callback URL: ${callbackUrl}`)
    
    // Only configure strategy if not placeholders
    if (!isPlaceholderValue(GOOGLE_CLIENT_ID) && !isPlaceholderValue(GOOGLE_CLIENT_SECRET)) {
        passport.use(
            new GoogleStrategy(
                {
                    clientID: GOOGLE_CLIENT_ID.trim(),
                    clientSecret: GOOGLE_CLIENT_SECRET.trim(),
                    callbackURL: callbackUrl,
                },
            async (accessToken, refreshToken, profile, done) => {
                try {
                    const email = profile.emails?.[0]?.value?.toLowerCase()
                    const name = profile.displayName || profile.name?.givenName || "User"

                    if (!email) {
                        return done(new Error("No email found in Google profile"), null)
                    }

                    // Check if user exists
                    let user = users.get(email)

                    if (!user) {
                        // Create new user from Google account
                        user = {
                            name,
                            email,
                            password: null, // OAuth users don't have passwords
                            provider: "google",
                            googleId: profile.id,
                            createdAt: new Date().toISOString(),
                        }
                        users.set(email, user)
                        saveUsers()
                    } else {
                        // Update existing user with Google ID if not set
                        if (!user.googleId) {
                            user.googleId = profile.id
                            user.provider = user.provider || "google"
                            users.set(email, user)
                            saveUsers()
                        }
                    }

                    return done(null, { email, name })
                } catch (error) {
                    return done(error, null)
                }
            }
        )
        )
        
        console.log(`[Google OAuth] Strategy configured successfully`)
        console.log(`[Google OAuth] ⚠️  IMPORTANT CHECKLIST:`)
        console.log(`[Google OAuth]    1. Verify Client ID in Google Console: https://console.cloud.google.com/apis/credentials`)
        console.log(`[Google OAuth]    2. Add callback URL: ${callbackUrl}`)
        console.log(`[Google OAuth]    3. Make sure OAuth consent screen is configured`)
        console.log(`[Google OAuth]    4. Client ID and Secret must match the same OAuth client`)
    } else {
        console.log(`[Google OAuth] Strategy NOT configured - placeholder values detected`)
        console.log(`[Google OAuth] Please replace placeholder values with real credentials from Google Console`)
    }
} else {
    console.log(`[Google OAuth] Strategy not configured - missing credentials in .env file`)
}

// Email and password validation functions are defined earlier in the file (after sanitizeInput)

// Authentication middleware with better error formatting
// Enhanced authentication middleware with cookie support
function authenticateToken(req, res, next) {
    // Try to get token from Authorization header first
    let token = null
    const authHeader = req.headers["authorization"]
    if (authHeader) {
        token = authHeader.split(" ")[1] // Bearer TOKEN
    }
    
    // Also check for token in secure httpOnly cookie
    if (!token && req.cookies && req.cookies.lumra_token) {
        token = req.cookies.lumra_token
    }

    if (!token) {
        res.status(401).json({
            success: false,
            error: {
                code: "AUTH_REQUIRED",
                message: "Authentication required. Please log in.",
                details: "This endpoint requires a valid authentication token. Please include your JWT token in the Authorization header as 'Bearer <token>' or log in to set a secure cookie."
            },
            timestamp: new Date().toISOString()
        })
        return
    }

    // Verify token with additional security checks
    jwt.verify(token, JWT_SECRET, { 
        issuer: 'lumra',
        audience: 'lumra-client'
    }, (err, user) => {
        if (err) {
            // Clear invalid cookie
            res.clearCookie('lumra_token', {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: 'strict',
                path: '/',
            })
            
            res.status(403).json({
                success: false,
                error: {
                    code: "AUTH_INVALID",
                    message: "Invalid or expired token. Please log in again.",
                    details: err.name === "TokenExpiredError" 
                        ? "Your session has expired. Please log in again."
                        : "The provided token is invalid or malformed."
                },
                timestamp: new Date().toISOString()
            })
            return
        }
        req.user = user
        next()
    })
}

const openAiKey = process.env.OPENAI_API_KEY
const anthropicKey = process.env.ANTHROPIC_API_KEY

const openaiClient = openAiKey ? new OpenAI({ apiKey: openAiKey }) : null
const anthropicClient = anthropicKey ? new Anthropic({ apiKey: anthropicKey }) : null

// Initialize RAG system
const DOCUMENTS_DIR = join(__dirname, "documents")
if (!existsSync(DOCUMENTS_DIR)) {
    mkdirSync(DOCUMENTS_DIR, { recursive: true })
    console.log(`[RAG] ✅ Created documents directory: ${DOCUMENTS_DIR}`)
}

// Initialize RAG when OpenAI client is available
if (openaiClient) {
    console.log(`[RAG] 🔄 Initializing RAG system...`)
    initializeRAG(openaiClient)
        .then(async (success) => {
            if (success) {
                console.log(`[RAG] ✅ RAG system initialized successfully`)
                // Verify RAG is actually available
                const { isRAGAvailable } = await import("./rag.js")
                const { isVectorDBAvailable } = await import("./vectorDB.js")
                console.log(`[RAG] 🔍 Verification: isRAGAvailable=${isRAGAvailable()}, isVectorDBAvailable=${isVectorDBAvailable()}`)
            } else {
                console.log(`[RAG] ⚠️  RAG system initialized with limitations (vector DB may not be available)`)
                console.log(`[RAG] 🔍 Checking status...`)
                const { isRAGAvailable } = await import("./rag.js")
                const { isVectorDBAvailable } = await import("./vectorDB.js")
                console.log(`[RAG] 🔍 Status: isRAGAvailable=${isRAGAvailable()}, isVectorDBAvailable=${isVectorDBAvailable()}`)
            }
        })
        .catch((error) => {
            console.error(`[RAG] ❌ RAG initialization failed: ${error.message}`)
            console.error(`[RAG] ❌ Error stack: ${error.stack}`)
        })
} else {
    console.log(`[RAG] ⚠️  RAG system not initialized - OpenAI client not available`)
}

// Configure multer for file uploads
const storage = multer.memoryStorage()
const upload = multer({
    storage,
    limits: {
        fileSize: parseInt(process.env.MAX_DOCUMENT_SIZE || "10485760", 10), // 10MB default
    },
    fileFilter: (req, file, cb) => {
        const allowedMimes = [
            "application/pdf",
            "text/plain",
            "text/markdown",
            "text/csv",
            "application/json",
            "text/xml",
        ]
        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true)
        } else {
            cb(new Error(`File type ${file.mimetype} not allowed. Supported: PDF, TXT, MD, CSV, JSON, XML`), false)
        }
    },
})

// Signup endpoint with rate limiting
app.post("/api/auth/signup", authLimiter, async (req, res) => {
    const { name, email, password } = req.body ?? {}

    // Validate all fields
    if (!name || !email || !password) {
        res.status(400).json({ error: "Name, email, and password are required" })
        return
    }

    const trimmedName = name.trim()
    const trimmedEmail = email.trim().toLowerCase()
    const trimmedPassword = password.trim()

    // Validate name
    if (trimmedName.length < 2) {
        res.status(400).json({ error: "Name must be at least 2 characters long" })
        return
    }

    // Validate email
    if (!isValidEmail(trimmedEmail)) {
        res.status(400).json({ error: "Please enter a valid email address" })
        return
    }

    // Validate password
    const passwordValidation = isValidPassword(trimmedPassword)
    if (!passwordValidation.valid) {
        res.status(400).json({ error: passwordValidation.error || "Invalid password" })
        return
    }

    // Check if user already exists
    if (users.has(trimmedEmail)) {
        res.status(409).json({ error: "An account with this email already exists" })
        return
    }

    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(trimmedPassword, 10)

        // Create user
        const user = {
            name: trimmedName,
            email: trimmedEmail,
            password: hashedPassword,
            createdAt: new Date().toISOString(),
        }

        users.set(trimmedEmail, user)
        saveUsers()

        // Generate JWT token with enhanced security
        const token = jwt.sign(
            { 
                email: trimmedEmail, 
                name: trimmedName,
                iat: Math.floor(Date.now() / 1000), // Issued at time
            }, 
            JWT_SECRET, 
            { 
                expiresIn: JWT_EXPIRES_IN,
                issuer: 'lumra',
                audience: 'lumra-client'
            }
        )

        // Set secure cookie for token (optional - can use httpOnly cookie instead of localStorage)
        const isProduction = process.env.NODE_ENV === "production"
        res.cookie('lumra_token', token, {
            httpOnly: true, // Prevent XSS attacks
            secure: isProduction, // HTTPS only in production
            sameSite: 'strict', // CSRF protection
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/',
        })

        res.status(201).json({
            message: "Account created successfully",
            token,
            user: { name: trimmedName, email: trimmedEmail },
        })
    } catch (error) {
        console.error("Signup error:", error)
        res.status(500).json({ error: "Failed to create account. Please try again." })
    }
})

// Login endpoint with rate limiting
app.post("/api/auth/login", authLimiter, async (req, res) => {
    const { email, password } = req.body ?? {}

    // Validate fields
    if (!email || !password) {
        res.status(400).json({ error: "Email and password are required" })
        return
    }

    const trimmedEmail = email.trim().toLowerCase()
    const trimmedPassword = password.trim()

    // Validate email format
    if (!isValidEmail(trimmedEmail)) {
        res.status(400).json({ error: "Please enter a valid email address" })
        return
    }

    // Check if user exists
    const user = users.get(trimmedEmail)
    if (!user) {
        res.status(401).json({ error: "Invalid email or password" })
        return
    }

    try {
        // Verify password (skip if OAuth user)
        if (!user.password) {
            res.status(401).json({ error: "This account uses social login. Please use Google to sign in." })
            return
        }

        const passwordMatch = await bcrypt.compare(trimmedPassword, user.password)
        if (!passwordMatch) {
            res.status(401).json({ error: "Invalid email or password" })
            return
        }

        // Generate JWT token with enhanced security
        const token = jwt.sign(
            { 
                email: user.email, 
                name: user.name,
                iat: Math.floor(Date.now() / 1000), // Issued at time
            }, 
            JWT_SECRET, 
            { 
                expiresIn: JWT_EXPIRES_IN,
                issuer: 'lumra',
                audience: 'lumra-client'
            }
        )

        // Set secure cookie for token (optional - can use httpOnly cookie instead of localStorage)
        const isProduction = process.env.NODE_ENV === "production"
        res.cookie('lumra_token', token, {
            httpOnly: true, // Prevent XSS attacks
            secure: isProduction, // HTTPS only in production
            sameSite: 'strict', // CSRF protection
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/',
        })

        res.json({
            message: "Login successful",
            token,
            user: { name: user.name, email: user.email },
        })
    } catch (error) {
        console.error("Login error:", error)
        res.status(500).json({ error: "Failed to log in. Please try again." })
    }
})

// Google OAuth routes - always register the route
app.get("/api/auth/google", (req, res) => {
    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
        // Get referer to redirect back to the same frontend origin
        const referer = req.headers.referer || req.headers.origin
        const frontendUrl = referer ? new URL(referer).origin : (allowedOrigins[0] || "http://localhost:5173")
        
        console.log("⚠️  Google OAuth accessed but not configured. Redirecting to:", frontendUrl)
        
        // Return HTML error page that redirects to frontend
        res.status(503).send(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>OAuth Not Configured</title>
    <meta http-equiv="refresh" content="2;url=${frontendUrl}?oauth_error=not_configured">
</head>
<body>
    <h2>Google OAuth is not configured</h2>
    <p>Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.</p>
    <p>Redirecting back to login page...</p>
    <script>
        setTimeout(() => {
            window.location.href = "${frontendUrl}?oauth_error=not_configured";
        }, 2000);
    </script>
</body>
</html>
        `)
        return
    }
    
    // Get frontend URL from referer for redirect after auth
    const referer = req.headers.referer || req.headers.origin
    let frontendUrl = allowedOrigins[0] || "http://localhost:5173"
    
    if (referer) {
        try {
            const refererUrl = new URL(referer)
            const matchingOrigin = allowedOrigins.find(origin => {
                try {
                    return new URL(origin).origin === refererUrl.origin
                } catch {
                    return false
                }
            })
            if (matchingOrigin) {
                frontendUrl = refererUrl.origin
            }
        } catch (e) {
            // Use default
        }
    }
    
    console.log("")
    console.log("=".repeat(80))
    console.log(`[Google OAuth] Initiating authentication flow...`)
    console.log(`   Client ID: ${GOOGLE_CLIENT_ID.substring(0, 30)}...`)
    console.log(`   Frontend URL: ${frontendUrl}`)
    console.log(`   Callback URL: ${process.env.GOOGLE_CALLBACK_URL || `http://localhost:${port}/api/auth/google/callback`}`)
    console.log("=".repeat(80))
    
    // Store frontend URL in session for callback redirect
    if (req.session) {
        req.session.oauthFrontendUrl = frontendUrl
    }
    
    // Initiate Google OAuth flow
    passport.authenticate("google", { 
        scope: ["profile", "email"]
    })(req, res)
})

// Handle Google OAuth callback
app.get("/api/auth/google/callback", (req, res, next) => {
    // Log callback attempt
    console.log("")
    console.log("=".repeat(80))
    console.log(`[Google OAuth Callback] Received at ${new Date().toISOString()}`)
    console.log(`   Query params:`, req.query)
    console.log(`   Referer:`, req.headers.referer)
    console.log(`   Origin:`, req.headers.origin)
    
    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
        // Get state from query or use default frontend URL
        const state = req.query.state
        const frontendUrl = state || allowedOrigins[0] || "http://localhost:5173"
        console.log("⚠️  OAuth callback received but not configured. Redirecting to:", frontendUrl)
        console.log("=".repeat(80))
        res.redirect(`${frontendUrl}?oauth_error=not_configured`)
        return
    }
    
    console.log("✅ Processing Google OAuth callback...")
    console.log("=".repeat(80))
    
    passport.authenticate("google", { 
        session: false, 
        failureRedirect: "/auth/error",
        failureMessage: true
    })(req, res, next)
}, (req, res) => {
    try {
        console.log("")
        console.log("=".repeat(80))
        console.log(`[Google OAuth Callback] Processing authentication result`)
        
        if (!req.user) {
            console.error("❌ No user data received from OAuth")
            throw new Error("No user data received from OAuth")
        }
        
        console.log(`✅ User authenticated: ${req.user.email}`)
        console.log(`   Name: ${req.user.name}`)
        
        // Generate JWT token for the authenticated user with enhanced security
        const token = jwt.sign(
            { 
                email: req.user.email, 
                name: req.user.name,
                iat: Math.floor(Date.now() / 1000),
            }, 
            JWT_SECRET, 
            {
                expiresIn: JWT_EXPIRES_IN,
                issuer: 'lumra',
                audience: 'lumra-client'
            }
        )

        // Set secure cookie for token
        const isProduction = process.env.NODE_ENV === "production"
        res.cookie('lumra_token', token, {
            httpOnly: true,
            secure: isProduction,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/',
        })

        // Try to get frontend URL from session, referer, or use default
        let frontendUrl = allowedOrigins[0] || "http://localhost:5173"
        
        // Priority: session > referer > default
        if (req.session && req.session.oauthFrontendUrl) {
            try {
                const sessionUrl = new URL(req.session.oauthFrontendUrl)
                const matchingOrigin = allowedOrigins.find(origin => {
                    try {
                        return new URL(origin).origin === sessionUrl.origin
                    } catch {
                        return false
                    }
                })
                if (matchingOrigin) {
                    frontendUrl = req.session.oauthFrontendUrl
                    console.log(`   Using frontend URL from session: ${frontendUrl}`)
                    // Clear session after use
                    delete req.session.oauthFrontendUrl
                }
            } catch (e) {
                console.log(`   Session URL invalid, trying referer...`)
            }
        }
        
        const referer = req.headers.referer
        if (referer && frontendUrl === (allowedOrigins[0] || "http://localhost:5173")) {
            try {
                const refererUrl = new URL(referer)
                // Check if referer matches one of our allowed origins
                const matchingOrigin = allowedOrigins.find(origin => {
                    try {
                        return new URL(origin).origin === refererUrl.origin
                    } catch {
                        return false
                    }
                })
                if (matchingOrigin) {
                    frontendUrl = refererUrl.origin
                    console.log(`   Using frontend URL from referer: ${frontendUrl}`)
                }
            } catch (e) {
                console.log(`   Referer invalid, using default: ${frontendUrl}`)
            }
        }
        
        console.log(`✅ OAuth successful! Redirecting to: ${frontendUrl}`)
        console.log("=".repeat(80))
        console.log("")
        res.redirect(`${frontendUrl}/?auth_callback=google&token=${token}`)
    } catch (error) {
        console.error("❌ OAuth callback error:", error)
        console.error("   Stack:", error.stack)
        console.log("=".repeat(80))
        console.log("")
        const frontendUrl = allowedOrigins[0] || "http://localhost:5173"
        res.redirect(`${frontendUrl}?oauth_error=callback_failed&message=${encodeURIComponent(error.message)}`)
    }
})

// Microsoft OAuth routes (placeholder - requires passport-azure-ad or similar)
app.get("/api/auth/microsoft", (req, res) => {
    const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID
    const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET
    
    if (!MICROSOFT_CLIENT_ID || !MICROSOFT_CLIENT_SECRET || isPlaceholderValue(MICROSOFT_CLIENT_ID) || isPlaceholderValue(MICROSOFT_CLIENT_SECRET)) {
        const referer = req.headers.referer || req.headers.origin
        const frontendUrl = referer ? new URL(referer).origin : (allowedOrigins[0] || "http://localhost:5173")
        
        res.status(503).send(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>OAuth Not Configured</title>
    <meta http-equiv="refresh" content="2;url=${frontendUrl}?oauth_error=not_configured">
</head>
<body>
    <h2>Microsoft OAuth is not configured</h2>
    <p>Please set MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET environment variables.</p>
    <p>Redirecting back to login page...</p>
    <script>
        setTimeout(() => {
            window.location.href = "${frontendUrl}?oauth_error=not_configured";
        }, 2000);
    </script>
</body>
</html>
        `)
        return
    }
    
    // TODO: Implement Microsoft OAuth with passport-azure-ad or similar
    res.status(501).json({
        success: false,
        error: "Microsoft OAuth is configured but not yet implemented. Please use Google OAuth or email/password login."
    })
})

app.get("/api/auth/microsoft/callback", (req, res) => {
    const frontendUrl = allowedOrigins[0] || "http://localhost:5173"
    res.redirect(`${frontendUrl}?oauth_error=not_implemented&provider=microsoft`)
})

// Apple OAuth routes (placeholder - requires passport-apple or similar)
app.get("/api/auth/apple", (req, res) => {
    const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID
    const APPLE_CLIENT_SECRET = process.env.APPLE_CLIENT_SECRET
    
    if (!APPLE_CLIENT_ID || !APPLE_CLIENT_SECRET || isPlaceholderValue(APPLE_CLIENT_ID) || isPlaceholderValue(APPLE_CLIENT_SECRET)) {
        const referer = req.headers.referer || req.headers.origin
        const frontendUrl = referer ? new URL(referer).origin : (allowedOrigins[0] || "http://localhost:5173")
        
        res.status(503).send(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>OAuth Not Configured</title>
    <meta http-equiv="refresh" content="2;url=${frontendUrl}?oauth_error=not_configured">
</head>
<body>
    <h2>Apple OAuth is not configured</h2>
    <p>Please set APPLE_CLIENT_ID and APPLE_CLIENT_SECRET environment variables.</p>
    <p>Redirecting back to login page...</p>
    <script>
        setTimeout(() => {
            window.location.href = "${frontendUrl}?oauth_error=not_configured";
        }, 2000);
    </script>
</body>
</html>
        `)
        return
    }
    
    // TODO: Implement Apple OAuth with passport-apple or similar
    res.status(501).json({
        success: false,
        error: "Apple OAuth is configured but not yet implemented. Please use Google OAuth or email/password login."
    })
})

app.get("/api/auth/apple/callback", (req, res) => {
    const frontendUrl = allowedOrigins[0] || "http://localhost:5173"
    res.redirect(`${frontendUrl}?oauth_error=not_implemented&provider=apple`)
})

// OAuth error page
app.get("/auth/error", (req, res) => {
    const referer = req.headers.referer
    let frontendUrl = allowedOrigins[0] || "http://localhost:5173"
    
    if (referer) {
        try {
            const refererUrl = new URL(referer)
            const matchingOrigin = allowedOrigins.find(origin => {
                try {
                    return new URL(origin).origin === refererUrl.origin
                } catch {
                    return false
                }
            })
            if (matchingOrigin) {
                frontendUrl = refererUrl.origin
            }
        } catch (e) {
            // Use default
        }
    }
    
    console.log("❌ OAuth authentication failed. Redirecting to:", frontendUrl)
    res.redirect(`${frontendUrl}?oauth_error=auth_failed`)
})

// Tunnel activation endpoint - visit this URL first to activate localtunnel
app.get("/tunnel-test", (_req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Tunnel Active</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }
        h1 { margin: 0 0 20px 0; }
        p { font-size: 18px; margin: 10px 0; }
        .status { color: #4ade80; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ Tunnel is Active!</h1>
        <p class="status">Your localtunnel connection is working</p>
        <p>You can now use Google OAuth</p>
        <p style="font-size: 14px; margin-top: 30px; opacity: 0.8;">
            Backend: ${process.env.GOOGLE_CALLBACK_URL || 'Not configured'}<br>
            Server: ${process.env.PORT || 5050}
        </p>
    </div>
</body>
</html>
    `)
})

// Enhanced health check endpoint with proper formatting
app.get("/health", (_req, res) => {
    const uptime = process.uptime()
    const memoryUsage = process.memoryUsage()
    const maintenance = loadMaintenanceMode()
    
    res.json({
        success: true,
        status: maintenance.enabled ? "maintenance" : "operational",
        data: {
            server: {
                uptime: Math.floor(uptime),
                uptimeFormatted: `${Math.floor(uptime / 60)}m ${Math.floor(uptime % 60)}s`,
                timestamp: new Date().toISOString(),
                nodeVersion: process.version,
                platform: process.platform,
                memory: {
                    used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + " MB",
                    total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + " MB",
                    rss: Math.round(memoryUsage.rss / 1024 / 1024) + " MB",
                },
            },
            maintenance: {
                enabled: maintenance.enabled,
                message: maintenance.message,
                updatedAt: maintenance.updatedAt
            },
            services: {
                openai: {
                    configured: Boolean(openAiKey),
                    status: maintenance.enabled ? "maintenance" : (openaiClient ? "ready" : "not configured"),
                },
                anthropic: {
                    configured: Boolean(anthropicKey),
                    status: maintenance.enabled ? "maintenance" : (anthropicClient ? "ready" : "not configured"),
                },
                googleOAuth: {
                    configured: Boolean(
                        GOOGLE_CLIENT_ID && 
                        GOOGLE_CLIENT_SECRET && 
                        !isPlaceholderValue(GOOGLE_CLIENT_ID) && 
                        !isPlaceholderValue(GOOGLE_CLIENT_SECRET)
                    ),
                    status: (
                        GOOGLE_CLIENT_ID && 
                        GOOGLE_CLIENT_SECRET && 
                        !isPlaceholderValue(GOOGLE_CLIENT_ID) && 
                        !isPlaceholderValue(GOOGLE_CLIENT_SECRET)
                    ) ? "ready" : "not configured",
                },
                microsoftOAuth: {
                    configured: Boolean(
                        process.env.MICROSOFT_CLIENT_ID && 
                        process.env.MICROSOFT_CLIENT_SECRET && 
                        !isPlaceholderValue(process.env.MICROSOFT_CLIENT_ID || "") && 
                        !isPlaceholderValue(process.env.MICROSOFT_CLIENT_SECRET || "")
                    ),
                    status: (
                        process.env.MICROSOFT_CLIENT_ID && 
                        process.env.MICROSOFT_CLIENT_SECRET && 
                        !isPlaceholderValue(process.env.MICROSOFT_CLIENT_ID || "") && 
                        !isPlaceholderValue(process.env.MICROSOFT_CLIENT_SECRET || "")
                    ) ? "ready" : "not configured",
                },
                appleOAuth: {
                    configured: Boolean(
                        process.env.APPLE_CLIENT_ID && 
                        process.env.APPLE_CLIENT_SECRET && 
                        !isPlaceholderValue(process.env.APPLE_CLIENT_ID || "") && 
                        !isPlaceholderValue(process.env.APPLE_CLIENT_SECRET || "")
                    ),
                    status: (
                        process.env.APPLE_CLIENT_ID && 
                        process.env.APPLE_CLIENT_SECRET && 
                        !isPlaceholderValue(process.env.APPLE_CLIENT_ID || "") && 
                        !isPlaceholderValue(process.env.APPLE_CLIENT_SECRET || "")
                    ) ? "ready" : "not configured",
                },
            },
            database: {
                users: users.size,
                userProfiles: userProfiles.size,
            },
        },
        timestamp: new Date().toISOString()
    })
})

// Detailed status endpoint (public but with limited info)
app.get("/api/status", apiLimiter, (_req, res) => {
    const uptime = process.uptime()
    const memoryUsage = process.memoryUsage()
    
    res.json({
        success: true,
        status: "operational",
        data: {
            server: {
                uptime: Math.floor(uptime),
                uptimeFormatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`,
                timestamp: new Date().toISOString(),
                nodeVersion: process.version,
                platform: process.platform,
                pid: process.pid,
                memory: {
                    heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024),
                    heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024),
                    rss: Math.round(memoryUsage.rss / 1024 / 1024),
                    external: Math.round(memoryUsage.external / 1024 / 1024),
                },
                cpuUsage: process.cpuUsage(),
            },
            services: {
                openai: {
                    configured: Boolean(openAiKey),
                    status: openaiClient ? "connected" : "disconnected",
                    model: process.env.OPENAI_MODEL || "gpt-4o-mini",
                },
                anthropic: {
                    configured: Boolean(anthropicKey),
                    status: anthropicClient ? "connected" : "disconnected",
                    model: process.env.ANTHROPIC_MODEL || "claude-3-5-sonnet-20240620",
                },
                googleOAuth: {
                    configured: Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
                    status: GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET ? "configured" : "not configured",
                    callbackUrl: GOOGLE_CLIENT_ID ? (process.env.GOOGLE_CALLBACK_URL || `http://localhost:${port}/api/auth/google/callback`) : null,
                },
            },
            database: {
                totalUsers: users.size,
                activeProfiles: userProfiles.size,
                storage: existsSync(USERS_FILE) ? "persistent" : "in-memory only",
            },
            endpoints: {
                public: ["/health", "/api/auth/signup", "/api/auth/login", "/api/auth/google", "/api/status", "/api/test-connection"],
                protected: ["/api/fuse", "/api/chatgpt", "/api/claude"],
            },
        },
        timestamp: new Date().toISOString()
    })
})

// Connection test endpoint with proper formatting
// Document upload endpoint for RAG
app.post("/api/documents/upload", authenticateToken, (req, res, next) => {
    upload.single("document")(req, res, (err) => {
        if (err) {
            log(`[RAG] ❌ Upload error: ${err.message}`, "error")
            return res.status(400).json({
                error: "File upload failed",
                message: err.message,
            })
        }
        next()
    })
}, async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                error: "No file uploaded",
                message: "Please select a PDF or text file to upload"
            })
        }

        const userId = req.user?.email || req.user?.id || "anonymous"
        const documentId = `doc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        
        log(`[RAG] 📄 Document upload request: ${req.file.originalname} (${req.file.size} bytes) by ${userId}`)

        // Check if RAG is available
        if (!isRAGAvailable()) {
            log(`[RAG] ⚠️  RAG not available - OpenAI client or Vector DB not initialized`, "error")
            return res.status(503).json({
                error: "RAG system not available",
                message: "Document processing requires OpenAI client and Vector DB to be initialized. Please check server configuration.",
            })
        }

        // Process and store document
        log(`[RAG] 🔄 Processing document: ${req.file.originalname}...`)
        const result = await processAndStoreDocument(
            req.file.buffer,
            req.file.mimetype,
            req.file.originalname,
            documentId,
            userId
        )

        // Optionally save file to disk for reference
        const userDocDir = join(DOCUMENTS_DIR, userId.replace(/[^a-zA-Z0-9]/g, "_"))
        if (!existsSync(userDocDir)) {
            mkdirSync(userDocDir, { recursive: true })
        }
        const filePath = join(userDocDir, `${documentId}_${req.file.originalname}`)
        writeFileSync(filePath, req.file.buffer)

        log(`[RAG] ✅ Document processed successfully: ${documentId} - ${result.chunks} chunks`)

        res.json({
            success: true,
            documentId,
            filename: req.file.originalname,
            chunks: result.chunks,
            preview: result.text,
            message: "Document uploaded and processed successfully",
        })
    } catch (error) {
        log(`[RAG] ❌ Document upload failed: ${error.message}`, "error")
        log(`[RAG] ❌ Error stack: ${error.stack}`, "error")
        res.status(500).json({
            error: "Failed to process document",
            message: error.message,
            details: process.env.NODE_ENV === "development" ? error.stack : undefined,
        })
    }
})

// Get user's documents
app.get("/api/documents", authenticateToken, async (req, res) => {
    try {
        const userId = req.user?.email || req.user?.id || "anonymous"
        
        // Get documents from vector DB
        const { getUserDocuments } = await import("./vectorDB.js")
        const documents = await getUserDocuments(userId)
        
        log(`[RAG] 📋 User ${userId} has ${documents.length} document(s)`)

        res.json({
            success: true,
            documents,
            count: documents.length,
        })
    } catch (error) {
        log(`[RAG] ❌ Failed to get documents: ${error.message}`, "error")
        res.status(500).json({
            error: "Failed to retrieve documents",
            message: error.message,
        })
    }
})

// DEBUG: Test RAG retrieval endpoint
app.get("/api/rag/debug", authenticateToken, async (req, res) => {
    try {
        const userId = req.user?.email || req.user?.id || "anonymous"
        const query = req.query.q || "test query"
        
        log(`[RAG DEBUG] Testing RAG for user: ${userId}, query: "${query}"`)
        
        const { getUserDocuments } = await import("./vectorDB.js")
        const { retrieveRelevantDocuments } = await import("./rag.js")
        
        const userDocs = await getUserDocuments(userId)
        const retrievedDocs = await retrieveRelevantDocuments(query, userId, 10)
        
        res.json({
            success: true,
            userId,
            userDocuments: userDocs.length,
            retrievedChunks: retrievedDocs.length,
            documents: userDocs,
            chunks: retrievedDocs.map(d => ({
                text: d.text.substring(0, 200),
                filename: d.metadata.filename,
                relevance: d.relevance
            }))
        })
    } catch (error) {
        log(`[RAG DEBUG] ❌ Error: ${error.message}`, "error")
        res.status(500).json({
            error: "Debug failed",
            message: error.message,
        })
    }
})

// Delete document
app.delete("/api/documents/:documentId", authenticateToken, async (req, res) => {
    try {
        const { documentId } = req.params
        const userId = req.user?.email || req.user?.id || "anonymous"

        const success = await removeDocument(documentId)

        if (success) {
            // Also delete file from disk if exists
            const userDocDir = join(DOCUMENTS_DIR, userId.replace(/[^a-zA-Z0-9]/g, "_"))
            const files = readFileSync ? [] : [] // Would need to read directory
            // File cleanup can be done here if needed

            log(`[RAG] ✅ Document deleted: ${documentId}`)
            res.json({
                success: true,
                message: "Document deleted successfully",
            })
        } else {
            res.status(404).json({
                error: "Document not found",
            })
        }
    } catch (error) {
        log(`[RAG] ❌ Failed to delete document: ${error.message}`, "error")
        res.status(500).json({
            error: "Failed to delete document",
            message: error.message,
        })
    }
})

// RAG status endpoint
app.get("/api/rag/status", authenticateToken, async (req, res) => {
    try {
        const { isRAGAvailable, isVectorDBAvailable } = await import("./rag.js")
        const { isVectorDBAvailable: vectorDBAvailable } = await import("./vectorDB.js")
        
        const ragAvailable = isRAGAvailable()
        const vectorAvailable = vectorDBAvailable()
        const openaiAvailable = openaiClient !== null
        
        res.json({
            success: true,
            rag: {
                available: ragAvailable,
                vectorDB: vectorAvailable,
                openai: openaiAvailable,
                status: ragAvailable ? "ready" : "not_ready",
                message: ragAvailable 
                    ? "RAG system is ready" 
                    : `RAG not available. Vector DB: ${vectorAvailable ? "ready" : "not ready"}, OpenAI: ${openaiAvailable ? "ready" : "not ready"}`,
            },
        })
    } catch (error) {
        res.status(500).json({
            success: false,
            error: "Failed to check RAG status",
            message: error.message,
        })
    }
})

app.get("/api/test-connection", apiLimiter, async (_req, res) => {
    const tests = {
        success: true,
        status: "testing",
        data: {
            server: {
                connected: true,
                status: "operational"
            },
            services: {},
        },
        timestamp: new Date().toISOString()
    }
    
    // Test OpenAI connection
    if (openaiClient) {
        try {
            // Quick test - just check if client is initialized
            tests.data.services.openai = {
                connected: true,
                status: "ready",
                message: "OpenAI client initialized and ready"
            }
        } catch (error) {
            tests.data.services.openai = {
                connected: false,
                status: "error",
                message: error.message
            }
            tests.success = false
        }
    } else {
        tests.data.services.openai = {
            connected: false,
            status: "not configured",
            message: "OpenAI API key not set in environment variables"
        }
    }
    
    // Test Anthropic connection
    if (anthropicClient) {
        try {
            tests.data.services.anthropic = {
                connected: true,
                status: "ready",
                message: "Anthropic client initialized and ready"
            }
        } catch (error) {
            tests.data.services.anthropic = {
                connected: false,
                status: "error",
                message: error.message
            }
            tests.success = false
        }
    } else {
        tests.data.services.anthropic = {
            connected: false,
            status: "not configured",
            message: "Anthropic API key not set in environment variables"
        }
    }
    
    tests.status = tests.success ? "all_services_ready" : "some_services_unavailable"
    res.json(tests)
})

// Simple status page for browser viewing
app.get("/", requireDeveloperAuth, (req, res) => {
    const profileCount = userProfiles.size
    const isOpenAIReady = Boolean(openAiKey)
    const isAnthropicReady = Boolean(anthropicKey)
    const developerUsername = req.session.developerUsername || 'Admin User'
    const developerEmail = req.session.developerEmail || 'admin@edu.com'
    const maintenance = loadMaintenanceMode()
    const analytics = loadAnalytics()
    
    // Calculate metrics for dashboard
    const totalStudents = users.size || 2547
    const activeCourses = 48
    const totalTeachers = 124
    const completionRate = 87
    
    res.send(`
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <title>Dashboard - EduAdmin</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            min-height: 100vh;
            display: flex;
            overflow: hidden;
        }

        /* Sidebar */
        .sidebar {
            width: 260px;
            background: #1a1a1a;
            color: #ffffff;
            border-right: 1px solid #2a2a2a;
            display: flex;
            flex-direction: column;
            height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            z-index: 10;
        }

        .sidebar-header {
            padding: 24px 20px;
            border-bottom: 1px solid #2a2a2a;
        }

        .sidebar-logo {
            font-size: 24px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: -0.5px;
        }

        .sidebar-content {
            flex: 1;
            overflow-y: auto;
            padding: 16px 12px;
        }

        .sidebar-menu {
            list-style: none;
        }

        .sidebar-menu-item {
            margin-bottom: 4px;
        }

        .sidebar-menu-button {
            width: 100%;
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            border-radius: 8px;
            background: transparent;
            border: none;
            color: #a0a0a0;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 14px;
            text-align: left;
            text-decoration: none;
        }

        .sidebar-menu-button:hover {
            background: #2a2a2a;
            color: #ffffff;
        }

        .sidebar-menu-button.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #ffffff;
            font-weight: 500;
        }

        .sidebar-menu-icon {
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }

        .sidebar-footer {
            padding: 20px;
            border-top: 1px solid #2a2a2a;
        }

        .user-profile {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            border-radius: 8px;
            background: #2a2a2a;
        }

        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
            font-weight: 600;
            font-size: 14px;
        }

        .user-info {
            flex: 1;
        }

        .user-name {
            font-size: 14px;
            font-weight: 500;
            color: #ffffff;
            margin-bottom: 2px;
        }

        .user-email {
            font-size: 12px;
            color: #a0a0a0;
        }

        /* Main Content */
        .main-content {
            flex: 1;
            margin-left: 260px;
            display: flex;
            flex-direction: column;
            height: 100vh;
            overflow: hidden;
            background: #0a0a0a;
        }

        .header {
            padding: 20px 32px;
            border-bottom: 1px solid #2a2a2a;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #0a0a0a;
        }

        .search-bar {
            flex: 1;
            max-width: 500px;
            padding: 12px 16px;
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            color: #ffffff;
            font-size: 14px;
            outline: none;
        }

        .search-bar::placeholder {
            color: #666666;
        }

        .header-actions {
            display: flex;
            gap: 16px;
            align-items: center;
        }

        .header-icon {
            width: 40px;
            height: 40px;
            border-radius: 8px;
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s;
            color: #a0a0a0;
            font-size: 18px;
        }

        .header-icon:hover {
            background: #2a2a2a;
            color: #ffffff;
        }

        /* Content Area */
        .content {
            flex: 1;
            overflow-y: auto;
            padding: 32px;
            background: #0a0a0a;
        }

        .welcome-message {
            font-size: 24px;
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 32px;
        }

        /* Metrics Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
            margin-bottom: 32px;
        }

        .metric-card {
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 24px;
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
        }

        .metric-info {
            flex: 1;
        }

        .metric-label {
            font-size: 14px;
            color: #a0a0a0;
            margin-bottom: 8px;
        }

        .metric-value {
            font-size: 32px;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 8px;
        }

        .metric-change {
            font-size: 12px;
            color: #10b981;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .metric-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }

        .metric-icon.blue {
            background: rgba(59, 130, 246, 0.2);
            color: #3b82f6;
        }

        .metric-icon.green {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
        }

        .metric-icon.purple {
            background: rgba(139, 92, 246, 0.2);
            color: #8b5cf6;
        }

        .metric-icon.orange {
            background: rgba(249, 115, 22, 0.2);
            color: #f97316;
        }

        /* Two Column Layout */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }

        .dashboard-card {
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 24px;
        }

        .card-title {
            font-size: 18px;
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 20px;
        }

        /* Popular Courses */
        .course-item {
            display: flex;
            flex-direction: column;
            gap: 8px;
            padding: 16px 0;
            border-bottom: 1px solid #2a2a2a;
        }

        .course-item:last-child {
            border-bottom: none;
        }

        .course-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .course-name {
            font-size: 14px;
            font-weight: 500;
            color: #ffffff;
        }

        .course-enrollment {
            font-size: 12px;
            color: #a0a0a0;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: #2a2a2a;
            border-radius: 4px;
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            border-radius: 4px;
            transition: width 0.3s;
        }

        .progress-text {
            font-size: 12px;
            color: #a0a0a0;
            margin-top: 4px;
        }

        /* Recent Activity */
        .activity-item {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 16px 0;
            border-bottom: 1px solid #2a2a2a;
        }

        .activity-item:last-child {
            border-bottom: none;
        }

        .activity-icon {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: #2a2a2a;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            flex-shrink: 0;
        }

        .activity-content {
            flex: 1;
        }

        .activity-text {
            font-size: 14px;
            color: #ffffff;
            margin-bottom: 4px;
        }

        .activity-time {
            font-size: 12px;
            color: #a0a0a0;
        }

        /* Floating AI Icon */
        .ai-assistant {
            position: fixed;
            bottom: 32px;
            right: 32px;
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
            transition: all 0.3s;
            z-index: 100;
            font-size: 24px;
        }

        .ai-assistant:hover {
            transform: scale(1.1);
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
        }

        /* Responsive */
        @media (max-width: 1200px) {
            .metrics-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            .main-content {
                margin-left: 0;
            }
            .metrics-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">EduAdmin</div>
        </div>
        <div class="sidebar-content">
            <ul class="sidebar-menu">
                <li class="sidebar-menu-item">
                    <a href="/" class="sidebar-menu-button active">
                        <span class="sidebar-menu-icon">📊</span>
                        <span>Dashboard</span>
                    </a>
                </li>
                <li class="sidebar-menu-item">
                    <a href="#" class="sidebar-menu-button">
                        <span class="sidebar-menu-icon">📚</span>
                        <span>Courses</span>
                    </a>
                </li>
                <li class="sidebar-menu-item">
                    <a href="#" class="sidebar-menu-button">
                        <span class="sidebar-menu-icon">👥</span>
                        <span>Students</span>
                    </a>
                </li>
                <li class="sidebar-menu-item">
                    <a href="#" class="sidebar-menu-button">
                        <span class="sidebar-menu-icon">👨‍🏫</span>
                        <span>Teachers</span>
                    </a>
                </li>
                <li class="sidebar-menu-item">
                    <a href="/analytics" class="sidebar-menu-button">
                        <span class="sidebar-menu-icon">🤖</span>
                        <span>AI Analytics</span>
                    </a>
                </li>
                <li class="sidebar-menu-item">
                    <a href="/demo-keys" class="sidebar-menu-button">
                        <span class="sidebar-menu-icon">🔑</span>
                        <span>Demo Keys</span>
                    </a>
                </li>
                <li class="sidebar-menu-item">
                    <a href="#" class="sidebar-menu-button">
                        <span class="sidebar-menu-icon">📈</span>
                        <span>Analytics</span>
                    </a>
                </li>
                <li class="sidebar-menu-item">
                    <a href="#" class="sidebar-menu-button">
                        <span class="sidebar-menu-icon">⚙️</span>
                        <span>Settings</span>
                    </a>
                </li>
            </ul>
        </div>
        <div class="sidebar-footer">
            <div class="user-profile">
                <div class="user-avatar">AD</div>
                <div class="user-info">
                    <div class="user-name">${developerUsername}</div>
                    <div class="user-email">${developerEmail}</div>
                </div>
            </div>
        </div>
    </aside>

    <!-- Main Content -->
    <main class="main-content">
        <header class="header">
            <input type="text" class="search-bar" placeholder="Search courses, students, teachers...">
            <div class="header-actions">
                <div class="header-icon">✉️</div>
                <div class="header-icon">🔔</div>
                <div class="header-icon">👤</div>
            </div>
        </header>

        <div class="content">
            <div class="welcome-message">
                Welcome back, ${developerUsername.split(' ')[0]}! Here's what's happening with your learning platform today.
            </div>

            <!-- Key Metrics -->
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-info">
                        <div class="metric-label">Total Students</div>
                        <div class="metric-value">${totalStudents.toLocaleString()}</div>
                        <div class="metric-change">
                            <span>↑</span>
                            <span>+12% from last month</span>
                        </div>
                    </div>
                    <div class="metric-icon blue">👥</div>
                </div>

                <div class="metric-card">
                    <div class="metric-info">
                        <div class="metric-label">Active Courses</div>
                        <div class="metric-value">${activeCourses}</div>
                        <div class="metric-change">
                            <span>↑</span>
                            <span>+5% from last month</span>
                        </div>
                    </div>
                    <div class="metric-icon green">📚</div>
                </div>

                <div class="metric-card">
                    <div class="metric-info">
                        <div class="metric-label">Teachers</div>
                        <div class="metric-value">${totalTeachers}</div>
                        <div class="metric-change">
                            <span>↑</span>
                            <span>+8% from last month</span>
                        </div>
                    </div>
                    <div class="metric-icon purple">🎓</div>
                </div>

                <div class="metric-card">
                    <div class="metric-info">
                        <div class="metric-label">Completion Rate</div>
                        <div class="metric-value">${completionRate}%</div>
                        <div class="metric-change">
                            <span>↑</span>
                            <span>+3% from last month</span>
                        </div>
                    </div>
                    <div class="metric-icon orange">📈</div>
                </div>
            </div>

            <!-- Popular Courses and Recent Activity -->
            <div class="dashboard-grid">
                <!-- Popular Courses -->
                <div class="dashboard-card">
                    <div class="card-title">Popular Courses</div>
                    <div class="course-item">
                        <div class="course-header">
                            <div class="course-name">Introduction to React</div>
                            <div class="course-enrollment">324 students</div>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 78%"></div>
                        </div>
                        <div class="progress-text">78% completion</div>
                    </div>
                    <div class="course-item">
                        <div class="course-header">
                            <div class="course-name">Advanced JavaScript</div>
                            <div class="course-enrollment">256 students</div>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 65%"></div>
                        </div>
                        <div class="progress-text">65% completion</div>
                    </div>
                    <div class="course-item">
                        <div class="course-header">
                            <div class="course-name">Python for Beginners</div>
                            <div class="course-enrollment">412 students</div>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 82%"></div>
                        </div>
                        <div class="progress-text">82% completion</div>
                    </div>
                    <div class="course-item">
                        <div class="course-header">
                            <div class="course-name">Web Design Fundamentals</div>
                            <div class="course-enrollment">198 students</div>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 54%"></div>
                        </div>
                        <div class="progress-text">54% completion</div>
                    </div>
                    <div class="course-item">
                        <div class="course-header">
                            <div class="course-name">Data Science Basics</div>
                            <div class="course-enrollment">287 students</div>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 71%"></div>
                        </div>
                        <div class="progress-text">71% completion</div>
                    </div>
                </div>

                <!-- Recent Activity -->
                <div class="dashboard-card">
                    <div class="card-title">Recent Activity</div>
                    <div class="activity-item">
                        <div class="activity-icon">✓</div>
                        <div class="activity-content">
                            <div class="activity-text">Sarah Johnson completed React Basics</div>
                            <div class="activity-time">2 min ago</div>
                        </div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon">📝</div>
                        <div class="activity-content">
                            <div class="activity-text">Mike Chen enrolled in Python Course</div>
                            <div class="activity-time">15 min ago</div>
                        </div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon">📄</div>
                        <div class="activity-content">
                            <div class="activity-text">Emily Brown submitted Assignment #5</div>
                            <div class="activity-time">1 hour ago</div>
                        </div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon">💬</div>
                        <div class="activity-content">
                            <div class="activity-text">John Smith commented on Discussion Forum</div>
                            <div class="activity-time">2 hours ago</div>
                        </div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon">✓</div>
                        <div class="activity-content">
                            <div class="activity-text">Lisa Anderson completed JavaScript Pro</div>
                            <div class="activity-time">3 hours ago</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Floating AI Assistant -->
    <div class="ai-assistant" title="AI Assistant">
        🤖
    </div>
</body>
</html>
    `)
})

// Analytics dashboard page (protected, shows basic stats)
// Users page - show all registered users

// Analytics dashboard page (protected, shows basic stats)
// Users page - show all registered users
app.get("/users", requireDeveloperAuth, (req, res) => {
    try {
        // Convert users Map to array and format for display
        const usersArray = Array.from(users.values()).map(user => ({
            email: user.email || 'N/A',
            name: user.name || 'N/A',
            provider: user.provider || (user.password ? 'email' : 'unknown'),
            hasPassword: Boolean(user.password),
            googleId: user.googleId || null,
            createdAt: user.createdAt || 'Unknown',
            loginMethod: user.provider === 'google' ? 'Google OAuth' : (user.password ? 'Email/Password' : 'Unknown')
        }))
        
        // Sort by creation date (newest first)
        usersArray.sort((a, b) => {
            const dateA = new Date(a.createdAt).getTime() || 0
            const dateB = new Date(b.createdAt).getTime() || 0
            return dateB - dateA
        })
        
        const totalUsers = usersArray.length
        const googleUsers = usersArray.filter(u => u.provider === 'google').length
        const emailUsers = usersArray.filter(u => u.provider !== 'google' && u.hasPassword).length
        
        res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registered Users - Lumra Backend</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 24px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 1200px;
            width: 100%;
            margin: 0 auto;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #e2e8f0;
        }
        h1 {
            color: #667eea;
            font-size: 2rem;
        }
        .nav-links {
            display: flex;
            gap: 15px;
            align-items: center;
        }
        .nav-links a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
            padding: 8px 16px;
            border-radius: 8px;
            transition: background 0.2s;
        }
        .nav-links a:hover {
            background: #f1f5f9;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
        }
        .stat-card h3 {
            font-size: 2.5rem;
            margin-bottom: 5px;
        }
        .stat-card p {
            opacity: 0.9;
            font-size: 0.9rem;
        }
        .users-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .users-table thead {
            background: #f8fafc;
        }
        .users-table th {
            padding: 16px;
            text-align: left;
            font-weight: 600;
            color: #0f172a;
            border-bottom: 2px solid #e2e8f0;
        }
        .users-table td {
            padding: 16px;
            border-bottom: 1px solid #e2e8f0;
            color: #475569;
        }
        .users-table tbody tr:hover {
            background: #f8fafc;
        }
        .users-table tbody tr:last-child td {
            border-bottom: none;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 999px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        .badge-google {
            background: #dbeafe;
            color: #1e40af;
        }
        .badge-email {
            background: #d1fae5;
            color: #065f46;
        }
        .badge-unknown {
            background: #f3f4f6;
            color: #374151;
        }
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #94a3b8;
        }
        .empty-state svg {
            width: 64px;
            height: 64px;
            margin-bottom: 20px;
            opacity: 0.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>👥 Registered Users</h1>
                <p style="color: #64748b; margin-top: 5px;">All users who have signed up or logged in</p>
            </div>
            <div class="nav-links">
                <a href="/">← Status</a>
                <a href="/analytics">Analytics</a>
                <a href="/users">Users</a>
                <a href="/logs">Logs</a>
                <a href="/logout">Logout</a>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>${totalUsers}</h3>
                <p>Total Users</p>
            </div>
            <div class="stat-card">
                <h3>${googleUsers}</h3>
                <p>Google OAuth</p>
            </div>
            <div class="stat-card">
                <h3>${emailUsers}</h3>
                <p>Email/Password</p>
            </div>
        </div>
        
        ${totalUsers > 0 ? `
        <table class="users-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Login Method</th>
                    <th>Provider</th>
                    <th>Created At</th>
                </tr>
            </thead>
            <tbody>
                ${usersArray.map(user => `
                <tr>
                    <td><strong>${user.name}</strong></td>
                    <td>${user.email}</td>
                    <td>
                        <span class="badge ${user.provider === 'google' ? 'badge-google' : (user.hasPassword ? 'badge-email' : 'badge-unknown')}">
                            ${user.loginMethod}
                        </span>
                    </td>
                    <td>${user.provider || 'N/A'}</td>
                    <td>${user.createdAt !== 'Unknown' ? new Date(user.createdAt).toLocaleString() : 'Unknown'}</td>
                </tr>
                `).join('')}
            </tbody>
        </table>
        ` : `
        <div class="empty-state">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path>
            </svg>
            <h2>No users registered yet</h2>
            <p>Users will appear here once they sign up or log in with Google OAuth</p>
        </div>
        `}
    </div>
</body>
</html>
        `)
    } catch (error) {
        console.error("Error loading users page:", error)
        res.status(500).send(`
            <h1>Error</h1>
            <p>Failed to load users: ${error.message}</p>
            <a href="/">← Back to Status</a>
        `)
    }
})

// Maintenance mode toggle endpoint (admin only)
app.post("/api/maintenance/toggle", (req, res, next) => {
    // Check authentication for API requests
    if (!req.session || !req.session.developerAuthenticated) {
        console.log(`[Maintenance Mode] Unauthorized toggle attempt from IP: ${req.ip}`)
        return res.status(401).json({ 
            success: false,
            error: "Unauthorized. Developer authentication required." 
        })
    }
    next()
}, (req, res) => {
    try {
        const { enabled, message } = req.body || {}
        console.log(`[Maintenance Mode] Toggle request: enabled=${enabled}, message="${message || 'default'}"`)
        
        const maintenance = saveMaintenanceMode(enabled, message)
        
        if (maintenance) {
            console.log(`[Maintenance Mode] ${maintenance.enabled ? '✅ ENABLED' : '❌ DISABLED'} by ${req.session.developerUsername || 'developer'}`)
            if (maintenance.enabled) {
                console.log(`[Maintenance Mode] Message: ${maintenance.message}`)
            }
            res.json({
                success: true,
                maintenance: maintenance
            })
        } else {
            console.error(`[Maintenance Mode] Failed to save maintenance mode`)
            res.status(500).json({ 
                success: false,
                error: "Failed to update maintenance mode" 
            })
        }
    } catch (error) {
        console.error("Error toggling maintenance mode:", error)
        res.status(500).json({ 
            success: false,
            error: error.message 
        })
    }
})

// Get maintenance mode status (admin only)
app.get("/api/maintenance/status", requireDeveloperAuth, (req, res) => {
    try {
        const maintenance = loadMaintenanceMode()
        res.json({
            success: true,
            maintenance: maintenance
        })
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.get("/analytics", requireDeveloperAuth, (req, res) => {
    try {
        const analytics = loadAnalytics()
        const avgResponseTime = analytics.responseTimes.length > 0
            ? Math.round(analytics.responseTimes.reduce((a, b) => a + b, 0) / analytics.responseTimes.length)
            : 0
        const totalTokens = analytics.totalTokens || 0
        const successRate = analytics.totalConversations > 0
            ? Math.round((analytics.fusedCalls / analytics.totalConversations) * 100)
            : 0

        res.send(`
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>AI Analytics - Lumra</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        /* CSS Variables from globals.css */
        :root {
            --font-size: 16px;
            --background: oklch(0.145 0 0);
            --foreground: oklch(0.985 0 0);
            --card: oklch(0.145 0 0);
            --card-foreground: oklch(0.985 0 0);
            --popover: oklch(0.145 0 0);
            --popover-foreground: oklch(0.985 0 0);
            --primary: oklch(0.985 0 0);
            --primary-foreground: oklch(0.205 0 0);
            --secondary: oklch(0.269 0 0);
            --secondary-foreground: oklch(0.985 0 0);
            --muted: oklch(0.269 0 0);
            --muted-foreground: oklch(0.708 0 0);
            --accent: oklch(0.269 0 0);
            --accent-foreground: oklch(0.985 0 0);
            --destructive: oklch(0.396 0.141 25.723);
            --destructive-foreground: oklch(0.637 0.237 25.331);
            --border: oklch(0.269 0 0);
            --input: oklch(0.269 0 0);
            --ring: oklch(0.439 0 0);
            --chart-1: oklch(0.488 0.243 264.376);
            --chart-2: oklch(0.696 0.17 162.48);
            --chart-3: oklch(0.769 0.188 70.08);
            --chart-4: oklch(0.627 0.265 303.9);
            --chart-5: oklch(0.645 0.246 16.439);
            --radius: 0.625rem;
            --sidebar: oklch(0.205 0 0);
            --sidebar-foreground: oklch(0.985 0 0);
            --sidebar-primary: oklch(0.488 0.243 264.376);
            --sidebar-primary-foreground: oklch(0.985 0 0);
            --sidebar-accent: oklch(0.269 0 0);
            --sidebar-accent-foreground: oklch(0.985 0 0);
            --sidebar-border: oklch(0.269 0 0);
            --sidebar-ring: oklch(0.439 0 0);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        html {
            font-size: var(--font-size);
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--background);
            color: var(--foreground);
            min-height: 100vh;
            display: flex;
            overflow: hidden;
        }

        /* Sidebar */
        .sidebar {
            width: 16rem;
            background: var(--sidebar);
            color: var(--sidebar-foreground);
            border-right: 1px solid var(--sidebar-border);
            display: flex;
            flex-direction: column;
            height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            z-index: 10;
        }

        .sidebar-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--sidebar-border);
        }

        .sidebar-logo {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--sidebar-foreground);
        }

        .sidebar-content {
            flex: 1;
            overflow-y: auto;
            padding: 0.5rem;
        }

        .sidebar-menu {
            list-style: none;
        }

        .sidebar-menu-item {
            margin-bottom: 0.25rem;
        }

        .sidebar-menu-button {
            width: 100%;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.625rem 0.75rem;
            border-radius: calc(var(--radius) - 2px);
            background: transparent;
            border: none;
            color: var(--sidebar-foreground);
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.875rem;
            text-align: left;
        }

        .sidebar-menu-button:hover {
            background: var(--sidebar-accent);
            color: var(--sidebar-accent-foreground);
        }

        .sidebar-menu-button.active {
            background: var(--sidebar-primary);
            color: var(--sidebar-primary-foreground);
            font-weight: 500;
        }

        .sidebar-menu-icon {
            width: 1rem;
            height: 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .sidebar-footer {
            padding: 1rem;
            border-top: 1px solid var(--sidebar-border);
        }

        /* Main Content */
        .main-content {
            flex: 1;
            margin-left: 16rem;
            display: flex;
            flex-direction: column;
            height: 100vh;
            overflow: hidden;
            background: linear-gradient(to bottom right, #000000, #0a0a0a, #000000);
        }

        .header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--background);
        }

        .header-title {
            font-size: 1.875rem;
            font-weight: 700;
            color: var(--foreground);
        }

        .header-actions {
            display: flex;
            gap: 0.75rem;
            align-items: center;
        }

        .btn {
            padding: 0.5rem 1rem;
            border-radius: calc(var(--radius) - 2px);
            border: 1px solid var(--border);
            background: var(--secondary);
            color: var(--secondary-foreground);
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn:hover {
            background: var(--accent);
            color: var(--accent-foreground);
        }

        .btn-primary {
            background: var(--primary);
            color: var(--primary-foreground);
            border-color: var(--primary);
        }

        .btn-primary:hover {
            opacity: 0.9;
        }

        /* Content Area */
        .content {
            flex: 1;
            overflow-y: auto;
            padding: 1.5rem;
        }

        /* Cards */
        .card {
            background: var(--card);
            color: var(--card-foreground);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .card-header {
            display: flex;
            flex-direction: column;
            gap: 0.375rem;
        }

        .card-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--foreground);
        }

        .card-description {
            font-size: 0.875rem;
            color: var(--muted-foreground);
        }

        .card-content {
            flex: 1;
        }

        /* Grid Layout */
        .grid {
            display: grid;
            gap: 1.5rem;
        }

        .grid-cols-1 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
        .grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        .grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }

        /* KPI Cards */
        .kpi-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .kpi-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }

        .kpi-icon {
            width: 2.5rem;
            height: 2.5rem;
            border-radius: calc(var(--radius) - 2px);
            background: var(--secondary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
        }

        .kpi-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--foreground);
            line-height: 1;
        }

        .kpi-label {
            font-size: 0.875rem;
            color: var(--muted-foreground);
        }

        /* Chart Container */
        .chart-container {
            position: relative;
            height: 300px;
            width: 100%;
        }

        /* Loading State */
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 3rem;
            color: var(--muted-foreground);
        }

        /* Responsive */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            .main-content {
                margin-left: 0;
            }
            .grid-cols-2, .grid-cols-3, .grid-cols-4 {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">Lumra</div>
        </div>
        <div class="sidebar-content">
            <ul class="sidebar-menu">
                <li class="sidebar-menu-item">
                    <a href="/" class="sidebar-menu-button">
                        <span class="sidebar-menu-icon">📊</span>
                        <span>Dashboard</span>
                    </a>
                </li>
                <li class="sidebar-menu-item">
                    <a href="/analytics" class="sidebar-menu-button active">
                        <span class="sidebar-menu-icon">🤖</span>
                        <span>AI Analytics</span>
                    </a>
                </li>
                <li class="sidebar-menu-item">
                    <a href="/users" class="sidebar-menu-button">
                        <span class="sidebar-menu-icon">👥</span>
                        <span>Users</span>
                    </a>
                </li>
                <li class="sidebar-menu-item">
                    <a href="/logs" class="sidebar-menu-button">
                        <span class="sidebar-menu-icon">📋</span>
                        <span>Logs</span>
                    </a>
                </li>
            </ul>
        </div>
        <div class="sidebar-footer">
            <a href="/logout" class="btn" style="width: 100%; justify-content: center;">Logout</a>
        </div>
    </aside>

    <!-- Main Content -->
    <main class="main-content">
        <header class="header">
            <h1 class="header-title">AI Analytics</h1>
            <div class="header-actions">
                <button class="btn" onclick="refreshData()">🔄 Refresh</button>
                <span id="last-updated" style="font-size: 0.875rem; color: var(--muted-foreground);"></span>
            </div>
        </header>

        <div class="content">
            <!-- KPI Cards -->
            <div class="grid grid-cols-4" style="margin-bottom: 1.5rem;">
                <div class="kpi-card">
                    <div class="kpi-header">
                        <div class="kpi-icon">💬</div>
                    </div>
                    <div class="kpi-value" id="stat-conversations">${analytics.totalConversations || 0}</div>
                    <div class="kpi-label">Total Conversations</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-header">
                        <div class="kpi-icon">⚡</div>
                    </div>
                    <div class="kpi-value" id="stat-response-time">${(avgResponseTime / 1000).toFixed(1)}s</div>
                    <div class="kpi-label">Avg Response Time</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-header">
                        <div class="kpi-icon">🔢</div>
                    </div>
                    <div class="kpi-value" id="stat-tokens">${(totalTokens / 1000).toFixed(1)}K</div>
                    <div class="kpi-label">Total Tokens</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-header">
                        <div class="kpi-icon">💰</div>
                    </div>
                    <div class="kpi-value" id="stat-cost">$${(analytics.totalCost || 0).toFixed(2)}</div>
                    <div class="kpi-label">Total Cost</div>
                </div>
            </div>

            <!-- Charts Grid -->
            <div class="grid grid-cols-2" style="margin-bottom: 1.5rem;">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">Daily Usage (Last 7 Days)</div>
                        <div class="card-description">Total requests per day</div>
                    </div>
                    <div class="card-content">
                        <div class="chart-container">
                            <canvas id="dailyChart"></canvas>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">Hourly Usage (Last 24 Hours)</div>
                        <div class="card-description">Requests by hour</div>
                    </div>
                    <div class="card-content">
                        <div class="chart-container">
                            <canvas id="hourlyChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-2" style="margin-bottom: 1.5rem;">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">AI Model Breakdown</div>
                        <div class="card-description">Usage by model type</div>
                    </div>
                    <div class="card-content">
                        <div class="chart-container">
                            <canvas id="modelChart"></canvas>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">Cost Breakdown</div>
                        <div class="card-description">Cost by provider</div>
                    </div>
                    <div class="card-content">
                        <div class="chart-container">
                            <canvas id="costChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">Response Time Distribution</div>
                        <div class="card-description">Distribution of response times</div>
                    </div>
                    <div class="card-content">
                        <div class="chart-container">
                            <canvas id="responseTimeChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        let charts = {};
        let refreshInterval;

        // Chart.js default configuration for dark theme
        Chart.defaults.color = 'rgba(255, 255, 255, 0.8)';
        Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';
        Chart.defaults.backgroundColor = 'rgba(255, 255, 255, 0.1)';

        async function loadChartData() {
            try {
                const response = await fetch('/api/analytics/charts', {
                    credentials: 'include'
                });
                if (!response.ok) throw new Error('Failed to fetch chart data');
                const data = await response.json();
                if (data.success && data.charts) {
                    updateCharts(data.charts);
                    updateStats();
                    document.getElementById('last-updated').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
                }
            } catch (error) {
                console.error('Error loading chart data:', error);
            }
        }

        async function updateStats() {
            try {
                const response = await fetch('/api/analytics', {
                    credentials: 'include'
                });
                const data = await response.json();
                if (data.success && data.analytics) {
                    const analytics = data.analytics;
                    document.getElementById('stat-conversations').textContent = analytics.totalConversations || 0;
                    const avgRT = analytics.averageResponseTime || 0;
                    document.getElementById('stat-response-time').textContent = (avgRT / 1000).toFixed(1) + 's';
                    document.getElementById('stat-tokens').textContent = ((analytics.totalTokens || 0) / 1000).toFixed(1) + 'K';
                    document.getElementById('stat-cost').textContent = '$' + (analytics.totalCost || 0).toFixed(2);
                }
            } catch (error) {
                console.error('Error updating stats:', error);
            }
        }

        function updateCharts(chartData) {
            // Chart colors matching the design (converted from oklch to rgba)
            const chartColors = {
                primary: 'rgba(102, 126, 234, 1)',      // oklch(0.488 0.243 264.376) - purple
                primaryAlpha: 'rgba(102, 126, 234, 0.2)',
                secondary: 'rgba(16, 185, 129, 1)',   // oklch(0.696 0.17 162.48) - green
                secondaryAlpha: 'rgba(16, 185, 129, 0.8)',
                tertiary: 'rgba(251, 191, 36, 1)',     // oklch(0.769 0.188 70.08) - yellow
                tertiaryAlpha: 'rgba(251, 191, 36, 0.8)',
                accent: 'rgba(139, 92, 246, 1)',      // oklch(0.627 0.265 303.9) - violet
                accentAlpha: 'rgba(139, 92, 246, 0.8)',
                destructive: 'rgba(239, 68, 68, 1)',  // oklch(0.396 0.141 25.723) - red
                destructiveAlpha: 'rgba(239, 68, 68, 0.8)',
                chart5: 'rgba(249, 115, 22, 1)',      // oklch(0.645 0.246 16.439) - orange
                chart5Alpha: 'rgba(249, 115, 22, 0.8)'
            };

            // Daily Usage Chart
            if (!charts.daily) {
                charts.daily = new Chart(document.getElementById('dailyChart'), {
                    type: 'line',
                    data: {
                        labels: chartData.dailyUsage.map(d => d.label),
                        datasets: [{
                            label: 'Requests',
                            data: chartData.dailyUsage.map(d => d.requests),
                            borderColor: chartColors.primary,
                            backgroundColor: chartColors.primaryAlpha,
                            fill: true,
                            tension: 0.4,
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                                titleColor: 'rgba(255, 255, 255, 0.9)',
                                bodyColor: 'rgba(255, 255, 255, 0.8)',
                                borderColor: 'rgba(255, 255, 255, 0.2)',
                                borderWidth: 1
                            }
                        },
                        scales: {
                            y: { 
                                beginAtZero: true,
                                ticks: { color: 'rgba(255, 255, 255, 0.8)' },
                                grid: { color: 'rgba(255, 255, 255, 0.1)' },
                                border: { color: 'rgba(255, 255, 255, 0.2)' }
                            },
                            x: {
                                ticks: { color: 'rgba(255, 255, 255, 0.8)' },
                                grid: { color: 'rgba(255, 255, 255, 0.1)' },
                                border: { color: 'rgba(255, 255, 255, 0.2)' }
                            }
                        }
                    }
                });
            } else {
                charts.daily.data.labels = chartData.dailyUsage.map(d => d.label);
                charts.daily.data.datasets[0].data = chartData.dailyUsage.map(d => d.requests);
                charts.daily.update();
            }

            // Hourly Usage Chart
            if (!charts.hourly) {
                charts.hourly = new Chart(document.getElementById('hourlyChart'), {
                    type: 'bar',
                    data: {
                        labels: chartData.hourlyUsage.map(h => h.label),
                        datasets: [{
                            label: 'Requests',
                            data: chartData.hourlyUsage.map(h => h.requests),
                            backgroundColor: chartColors.secondaryAlpha
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                                titleColor: 'rgba(255, 255, 255, 0.9)',
                                bodyColor: 'rgba(255, 255, 255, 0.8)',
                                borderColor: 'rgba(255, 255, 255, 0.2)',
                                borderWidth: 1
                            }
                        },
                        scales: {
                            y: { 
                                beginAtZero: true,
                                ticks: { color: 'rgba(255, 255, 255, 0.8)' },
                                grid: { color: 'rgba(255, 255, 255, 0.1)' },
                                border: { color: 'rgba(255, 255, 255, 0.2)' }
                            },
                            x: {
                                ticks: { color: 'rgba(255, 255, 255, 0.8)' },
                                grid: { color: 'rgba(255, 255, 255, 0.1)' },
                                border: { color: 'rgba(255, 255, 255, 0.2)' }
                            }
                        }
                    }
                });
            } else {
                charts.hourly.data.labels = chartData.hourlyUsage.map(h => h.label);
                charts.hourly.data.datasets[0].data = chartData.hourlyUsage.map(h => h.requests);
                charts.hourly.update();
            }

            // Model Breakdown Chart
            if (!charts.model) {
                charts.model = new Chart(document.getElementById('modelChart'), {
                    type: 'doughnut',
                    data: {
                        labels: ['ChatGPT', 'Claude', 'Fused', 'Failed'],
                        datasets: [{
                            data: [
                                chartData.modelBreakdown.chatgpt || 0,
                                chartData.modelBreakdown.claude || 0,
                                chartData.modelBreakdown.fused || 0,
                                chartData.modelBreakdown.failed || 0
                            ],
                            backgroundColor: [
                                chartColors.secondaryAlpha,
                                chartColors.tertiaryAlpha,
                                chartColors.accentAlpha,
                                chartColors.destructiveAlpha
                            ],
                            borderWidth: 2,
                            borderColor: 'rgba(0, 0, 0, 0.3)'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { 
                                position: 'bottom',
                                labels: { 
                                    color: 'rgba(255, 255, 255, 0.9)',
                                    padding: 15,
                                    font: { size: 12 }
                                }
                            },
                            tooltip: {
                                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                                titleColor: 'rgba(255, 255, 255, 0.9)',
                                bodyColor: 'rgba(255, 255, 255, 0.8)',
                                borderColor: 'rgba(255, 255, 255, 0.2)',
                                borderWidth: 1
                            }
                        }
                    }
                });
            } else {
                charts.model.data.datasets[0].data = [
                    chartData.modelBreakdown.chatgpt || 0,
                    chartData.modelBreakdown.claude || 0,
                    chartData.modelBreakdown.fused || 0,
                    chartData.modelBreakdown.failed || 0
                ];
                charts.model.update();
            }

            // Cost Breakdown Chart
            if (!charts.cost) {
                charts.cost = new Chart(document.getElementById('costChart'), {
                    type: 'bar',
                    data: {
                        labels: ['OpenAI', 'Anthropic', 'Total'],
                        datasets: [{
                            label: 'Cost ($)',
                            data: [
                                chartData.costBreakdown.openai || 0,
                                chartData.costBreakdown.anthropic || 0,
                                chartData.costBreakdown.total || 0
                            ],
                            backgroundColor: [
                                chartColors.primaryAlpha,
                                chartColors.accentAlpha,
                                chartColors.chart5Alpha
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                                titleColor: 'rgba(255, 255, 255, 0.9)',
                                bodyColor: 'rgba(255, 255, 255, 0.8)',
                                borderColor: 'rgba(255, 255, 255, 0.2)',
                                borderWidth: 1,
                                callbacks: {
                                    label: function(context) {
                                        return 'Cost: $' + context.parsed.y.toFixed(4);
                                    }
                                }
                            }
                        },
                        scales: {
                            y: { 
                                beginAtZero: true,
                                ticks: { 
                                    color: 'rgba(255, 255, 255, 0.8)',
                                    callback: function(value) {
                                        return '$' + value.toFixed(2);
                                    }
                                },
                                grid: { color: 'rgba(255, 255, 255, 0.1)' },
                                border: { color: 'rgba(255, 255, 255, 0.2)' }
                            },
                            x: {
                                ticks: { color: 'rgba(255, 255, 255, 0.8)' },
                                grid: { color: 'rgba(255, 255, 255, 0.1)' },
                                border: { color: 'rgba(255, 255, 255, 0.2)' }
                            }
                        }
                    }
                });
            } else {
                charts.cost.data.datasets[0].data = [
                    chartData.costBreakdown.openai || 0,
                    chartData.costBreakdown.anthropic || 0,
                    chartData.costBreakdown.total || 0
                ];
                charts.cost.update();
            }

            // Response Time Distribution Chart
            if (!charts.responseTime) {
                charts.responseTime = new Chart(document.getElementById('responseTimeChart'), {
                    type: 'bar',
                    data: {
                        labels: chartData.responseTimeDistribution.map(r => r.label),
                        datasets: [{
                            label: 'Count',
                            data: chartData.responseTimeDistribution.map(r => r.count),
                            backgroundColor: chartColors.tertiaryAlpha
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                                titleColor: 'rgba(255, 255, 255, 0.9)',
                                bodyColor: 'rgba(255, 255, 255, 0.8)',
                                borderColor: 'rgba(255, 255, 255, 0.2)',
                                borderWidth: 1
                            }
                        },
                        scales: {
                            y: { 
                                beginAtZero: true,
                                ticks: { color: 'rgba(255, 255, 255, 0.8)' },
                                grid: { color: 'rgba(255, 255, 255, 0.1)' },
                                border: { color: 'rgba(255, 255, 255, 0.2)' }
                            },
                            x: {
                                ticks: { color: 'rgba(255, 255, 255, 0.8)' },
                                grid: { color: 'rgba(255, 255, 255, 0.1)' },
                                border: { color: 'rgba(255, 255, 255, 0.2)' }
                            }
                        }
                    }
                });
            } else {
                charts.responseTime.data.labels = chartData.responseTimeDistribution.map(r => r.label);
                charts.responseTime.data.datasets[0].data = chartData.responseTimeDistribution.map(r => r.count);
                charts.responseTime.update();
            }
        }

        function refreshData() {
            loadChartData();
            updateStats();
        }

        // Initialize on load
        window.addEventListener('load', () => {
            loadChartData();
            refreshInterval = setInterval(loadChartData, 30000); // Refresh every 30 seconds
        });

        // Cleanup on unload
        window.addEventListener('beforeunload', () => {
            if (refreshInterval) clearInterval(refreshInterval);
        });
    </script>
</body>
</html>
        `)
    } catch (error) {
        console.error("Error loading analytics page:", error)
        res.status(500).send(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Error</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 24px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            text-align: center;
        }
        h1 { color: #ef4444; margin-bottom: 16px; }
        p { color: #64748b; margin-bottom: 24px; }
        a { color: #667eea; text-decoration: none; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <h1>❌ Error Loading Analytics</h1>
        <p>${error.message}</p>
        <a href="/">← Back to Status</a>
    </div>
</body>
</html>
        `)
    }
})

app.post("/api/chatgpt", async (req, res) => {
    // Check maintenance mode
    const maintenance = loadMaintenanceMode()
    if (maintenance.enabled) {
        res.status(503).json({ 
            error: "AI services are currently under maintenance",
            message: maintenance.message,
            maintenance: true
        })
        return
    }

    if (!openaiClient) {
        res.status(500).json({ error: "OpenAI API key not configured on the server" })
        return
    }

    const { prompt, system, temperature = 0.7, model } = req.body ?? {}

    if (!prompt || typeof prompt !== "string") {
        res.status(400).json({ error: "Prompt is required" })
        return
    }

    const resolvedModel = model || process.env.OPENAI_MODEL || "gpt-4o-mini"

    try {
        const completion = await openaiClient.chat.completions.create({
            model: resolvedModel,
            temperature,
            messages: [
                ...(system ? [{ role: "system", content: system }] : []),
                { role: "user", content: prompt },
            ],
        })

        res.json({
            response: completion.choices[0]?.message?.content || "",
            model: resolvedModel,
        })
    } catch (error) {
        console.error("OpenAI error:", error)
        res.status(500).json({ error: "OpenAI request failed", details: error.message })
    }
})

app.post("/api/anthropic", async (req, res) => {
    // Check maintenance mode
    const maintenance = loadMaintenanceMode()
    if (maintenance.enabled) {
        res.status(503).json({ 
            error: "AI services are currently under maintenance",
            message: maintenance.message,
            maintenance: true
        })
        return
    }

    if (!anthropicClient) {
        res.status(500).json({ error: "Anthropic API key not configured on the server" })
        return
    }

    const { prompt, system, temperature = 0.7, maxTokens, model } = req.body ?? {}

    if (!prompt || typeof prompt !== "string") {
        res.status(400).json({ error: "Prompt is required" })
        return
    }

    const resolvedModel = model || process.env.ANTHROPIC_MODEL || "claude-3-5-sonnet-20240620"
    const resolvedMaxTokens =
        typeof maxTokens === "number" ? maxTokens : Number(process.env.ANTHROPIC_MAX_TOKENS) || 1024

    try {
        const completion = await anthropicClient.messages.create({
            model: resolvedModel,
            max_tokens: resolvedMaxTokens,
            temperature,
            messages: [
                ...(system ? [{ role: "user", content: system }] : []),
                { role: "user", content: prompt },
            ],
        })

        res.json({
            response: completion.content[0]?.text || "",
            model: resolvedModel,
        })
    } catch (error) {
        console.error("Anthropic error:", error)
        res.status(500).json({ error: "Anthropic request failed", details: error.message })
    }
})

app.post("/api/chatgpt", async (req, res) => {
    // Check maintenance mode
    const maintenance = loadMaintenanceMode()
    if (maintenance.enabled) {
        res.status(503).json({ 
            error: "AI services are currently under maintenance",
            message: maintenance.message,
            maintenance: true
        })
        return
    }

    if (!openaiClient) {
        res.status(500).json({ error: "OpenAI API key not configured on the server" })
        return
    }

    const { prompt, system, temperature = 0.7, model } = req.body ?? {}

    if (!prompt || typeof prompt !== "string") {
        res.status(400).json({ error: "Prompt is required" })
        return
    }

    const resolvedModel = model || process.env.OPENAI_MODEL || "gpt-4o-mini"

    try {
        const completion = await openaiClient.chat.completions.create({
            model: resolvedModel,
            temperature,
            messages: [
                ...(system ? [{ role: "system", content: system }] : []),
                { role: "user", content: prompt },
            ],
        })

        res.json({
            response: completion.choices[0]?.message?.content || "",
            model: resolvedModel,
        })
    } catch (error) {
        console.error("OpenAI error:", error)
        res.status(500).json({ error: "OpenAI request failed", details: error.message })
    }
})

app.post("/api/claude", async (req, res) => {
    // Check maintenance mode
    const maintenance = loadMaintenanceMode()
    if (maintenance.enabled) {
        res.status(503).json({ 
            error: "AI services are currently under maintenance",
            message: maintenance.message,
            maintenance: true
        })
        return
    }

    if (!anthropicClient) {
        res.status(500).json({ error: "Anthropic API key not configured on the server" })
        return
    }

    const { prompt, system, temperature = 0.7, maxTokens, model } = req.body ?? {}

    if (!prompt || typeof prompt !== "string") {
        res.status(400).json({ error: "Prompt is required" })
        return
    }

    const resolvedModel = model || process.env.ANTHROPIC_MODEL || "claude-3-5-sonnet-20240620"
    const resolvedMaxTokens =
        typeof maxTokens === "number" ? maxTokens : Number(process.env.ANTHROPIC_MAX_TOKENS) || 1024

    try {
        const completion = await anthropicClient.messages.create({
            model: resolvedModel,
            max_tokens: resolvedMaxTokens,
            temperature,
            messages: [
                ...(system ? [{ role: "user", content: system }] : []),
                { role: "user", content: prompt },
            ],
        })

        res.json({
            response: completion.content[0]?.text || "",
            model: resolvedModel,
        })
    } catch (error) {
        console.error("Anthropic error:", error)
        res.status(500).json({ error: "Anthropic request failed", details: error.message })
    }
})

app.post("/api/chat", async (req, res) => {
    res.status(501).json({ error: "Chat endpoint not implemented" })
})

app.post("/api/chatgpt", async (req, res) => {
    // Check maintenance mode
    const maintenance = loadMaintenanceMode()
    if (maintenance.enabled) {
        res.status(503).json({ 
            error: "AI services are currently under maintenance",
            message: maintenance.message,
            maintenance: true
        })
        return
    }

    if (!openaiClient) {
        res.status(500).json({ error: "OpenAI API key not configured on the server" })
        return
    }

    const { prompt, system, temperature = 0.7, model } = req.body ?? {}

    if (!prompt || typeof prompt !== "string") {
        res.status(400).json({ error: "Prompt is required" })
        return
    }

    const resolvedModel = model || process.env.OPENAI_MODEL || "gpt-4o-mini"

    try {
        const completion = await openaiClient.chat.completions.create({
            model: resolvedModel,
            temperature,
            messages: [
                ...(system ? [{ role: "system", content: system }] : []),
                { role: "user", content: prompt },
            ],
        })

        res.json({
            reply: completion.choices[0]?.message?.content ?? "",
            model: resolvedModel,
        })
    } catch (error) {
        console.error("OpenAI error:", error)
        res.status(500).json({ error: "OpenAI request failed", details: error.message })
    }
})

// Server logs page (protected, shows live server logs)
app.get("/logs", requireDeveloperAuth, (req, res) => {
    try {
        // Read server log file
        let logContent = ""
        let logLines = []
        
        if (existsSync(LOG_FILE)) {
            try {
                logContent = readFileSync(LOG_FILE, "utf-8")
                logLines = logContent.split('\n').filter(line => line.trim().length > 0)
            } catch (error) {
                logContent = `Error reading log file: ${error.message}`
            }
        } else {
            logContent = "No log file found. Logs will appear here once the server starts logging."
        }
        
        // Get last 500 lines (most recent)
        const recentLogs = logLines.slice(-500).reverse() // Newest first
        const logCount = recentLogs.length
        
        res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Logs - Lumra Backend</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: #0f172a;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            max-width: 1400px;
            margin: 0 auto;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        h1 {
            color: white;
            font-size: 1.5rem;
            font-weight: 700;
        }
        .nav-links {
            display: flex;
            gap: 12px;
            align-items: center;
        }
        .nav-links a {
            color: white;
            text-decoration: none;
            font-weight: 600;
            padding: 8px 16px;
            border-radius: 6px;
            background: rgba(255,255,255,0.2);
            transition: background 0.2s;
            font-size: 0.875rem;
        }
        .nav-links a:hover {
            background: rgba(255,255,255,0.3);
        }
        .controls {
            background: #1e293b;
            padding: 15px 30px;
            display: flex !important;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #334155;
            gap: 20px;
            flex-wrap: wrap;
        }
        @media (max-width: 768px) {
            .controls {
                flex-direction: column;
                align-items: stretch;
            }
            .search-bar {
                max-width: 100%;
                margin-bottom: 10px;
            }
        }
        .search-bar {
            flex: 1;
            max-width: 400px;
            min-width: 200px;
            display: block !important;
            visibility: visible !important;
        }
        .search-input {
            width: 100%;
            background: #0f172a;
            border: 1px solid #334155;
            color: #e2e8f0;
            padding: 10px 15px;
            border-radius: 8px;
            font-size: 0.875rem;
            transition: border-color 0.2s;
            display: block !important;
            visibility: visible !important;
        }
        .search-input:focus {
            outline: none;
            border-color: #667eea;
        }
        .search-input::placeholder {
            color: #64748b;
        }
        .info-text {
            color: #94a3b8;
            font-size: 0.875rem;
            margin-right: 10px;
        }
        .controls button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.875rem;
            transition: transform 0.2s, box-shadow 0.2s;
            white-space: nowrap;
        }
        .controls button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .log-container {
            background: #0f172a;
            padding: 0;
            max-height: calc(100vh - 250px);
            overflow-y: auto;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
        }
        .log-table {
            width: 100%;
            border-collapse: collapse;
            background: #0f172a;
        }
        .log-table thead {
            position: sticky;
            top: 0;
            z-index: 10;
            background: #1e293b;
        }
        .log-table th {
            padding: 12px 20px;
            text-align: left;
            color: #94a3b8;
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid #334155;
        }
        .time-column {
            width: 220px;
            min-width: 220px;
        }
        .message-column {
            width: auto;
        }
        .log-row {
            border-bottom: 1px solid #1e293b;
            transition: background-color 0.1s;
        }
        .log-row:hover {
            background-color: #1e293b;
        }
        .log-row.error {
            background-color: rgba(239, 68, 68, 0.1);
        }
        .log-row.error:hover {
            background-color: rgba(239, 68, 68, 0.15);
        }
        .log-row.success {
            background-color: rgba(16, 185, 129, 0.1);
        }
        .log-row.hidden {
            display: none;
        }
        .time-cell {
            padding: 10px 20px;
            color: #64748b;
            font-size: 0.8125rem;
            white-space: nowrap;
            vertical-align: top;
            border-right: 1px solid #1e293b;
        }
        .message-cell {
            padding: 10px 20px;
            color: #e2e8f0;
            font-size: 0.875rem;
            word-break: break-word;
            line-height: 1.5;
        }
        .log-row.error .message-cell {
            color: #fca5a5;
        }
        .log-row.success .message-cell {
            color: #86efac;
        }
        .log-line {
            padding: 4px 8px;
            margin: 2px 0;
            border-left: 3px solid transparent;
            word-wrap: break-word;
            font-size: 0.875rem;
            line-height: 1.6;
        }
        .log-line:hover {
            background: rgba(102, 126, 234, 0.1);
            border-left-color: #667eea;
        }
        .log-line.error {
            color: #f87171;
            background: rgba(239, 68, 68, 0.1);
            border-left-color: #ef4444;
            font-weight: 600;
        }
        .error-alert {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            padding: 20px 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(239, 68, 68, 0.5), 0 0 20px rgba(239, 68, 68, 0.8);
            font-size: 1.5rem;
            font-weight: 700;
            z-index: 10000;
            display: none;
            animation: errorPulse 0.5s ease-in-out;
            border: 3px solid rgba(255, 255, 255, 0.3);
        }
        .error-alert.show {
            display: block;
            animation: errorPulse 0.5s ease-in-out, errorShake 0.5s ease-in-out;
        }
        @keyframes errorPulse {
            0%, 100% { transform: translateX(-50%) scale(1); }
            50% { transform: translateX(-50%) scale(1.05); }
        }
        @keyframes errorShake {
            0%, 100% { transform: translateX(-50%) translateX(0); }
            25% { transform: translateX(-50%) translateX(-10px); }
            75% { transform: translateX(-50%) translateX(10px); }
        }
        .activity-indicator {
            position: fixed;
            top: 80px;
            right: 20px;
            background: rgba(16, 185, 129, 0.9);
            color: white;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 600;
            z-index: 9999;
            display: none;
            animation: slideIn 0.3s ease-out;
        }
        .activity-indicator.show {
            display: block;
        }
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        .log-line.refined {
            color: #60a5fa;
            background: rgba(96, 165, 250, 0.1);
        }
        .log-line.chatgpt {
            color: #34d399;
        }
        .log-line.claude {
            color: #fbbf24;
        }
        .log-line.success {
            color: #10b981;
        }
        .timestamp {
            color: #64748b;
            margin-right: 8px;
        }
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #64748b;
        }
        .empty-state-icon {
            font-size: 4rem;
            margin-bottom: 16px;
        }
        /* Scrollbar styling */
        .log-container::-webkit-scrollbar {
            width: 8px;
        }
        .log-container::-webkit-scrollbar-track {
            background: #1e293b;
        }
        .log-container::-webkit-scrollbar-thumb {
            background: #475569;
            border-radius: 4px;
        }
        .log-container::-webkit-scrollbar-thumb:hover {
            background: #64748b;
        }
        .chart-section {
            background: #1e293b;
            padding: 20px 30px;
            border-bottom: 2px solid #334155;
        }
        .chart-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .chart-header h3 {
            color: #e2e8f0;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .chart-legend {
            display: flex;
            gap: 15px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
            color: #94a3b8;
            font-size: 0.75rem;
        }
        .legend-color {
            width: 12px;
            height: 12px;
            border-radius: 2px;
        }
        .chart-container {
            height: 200px;
            position: relative;
        }
        #activityChart {
            width: 100%;
            height: 200px;
            display: block;
        }
    </style>
</head>
<body>
    <!-- Error Alert Banner -->
    <div id="errorAlert" class="error-alert">
        ⚠️ ERROR DETECTED IN LOGS ⚠️
    </div>
    
    <!-- Activity Indicator -->
    <div id="activityIndicator" class="activity-indicator">
        📝 New log activity
    </div>
    
    <div class="container">
        <div class="header">
            <h1>📋 Server Logs</h1>
            <div class="nav-links">
                <a href="/">Status</a>
                <a href="/analytics">Analytics</a>
                <a href="/users">Users</a>
                <a href="/logout">Logout</a>
            </div>
        </div>
        
        <div class="controls">
            <div class="search-bar">
                <input type="text" id="searchInput" placeholder="Search..." class="search-input">
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <span class="info-text" id="autoRefreshStatus">Auto-refresh: OFF</span>
                <button id="refreshBtn" onclick="refreshLogs()">🔄 Refresh</button>
                <button id="autoRefreshBtn" onclick="toggleAutoRefresh()">▶️ Auto-Refresh</button>
                <button id="clearBtn" onclick="clearLogs()">🗑️ Clear</button>
                <button id="testErrorBtn" onclick="testError()" style="background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);">⚠️ Test Error</button>
                <button id="testActivityBtn" onclick="testActivity()" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%);">📝 Test Activity</button>
            </div>
        </div>
        
        <div class="chart-section" id="chartSection">
            <div class="chart-header">
                <h3>LOGS OVER PROCESS DURATION</h3>
                <div class="chart-legend">
                    <span class="legend-item"><span class="legend-color" style="background: #3b82f6;"></span> Info</span>
                    <span class="legend-item"><span class="legend-color" style="background: #10b981;"></span> Success</span>
                    <span class="legend-item"><span class="legend-color" style="background: #ef4444;"></span> Error</span>
                </div>
            </div>
            <div class="chart-container">
                <canvas id="activityChart"></canvas>
            </div>
        </div>
        
        <div class="log-container" id="logContainer">
            ${recentLogs.length > 0 ? `
            <table class="log-table">
                <thead>
                    <tr>
                        <th class="time-column">Time</th>
                        <th class="message-column">Message</th>
                    </tr>
                </thead>
                <tbody id="logTableBody">
                    ${recentLogs.map(line => {
                // Color code log lines
                let className = ''
                        const upperLine = line.toUpperCase()
                        // Error detection - only for actual errors
                        if (upperLine.includes('ERROR') || upperLine.includes('❌') || 
                            upperLine.includes('FAILED') || upperLine.includes('EXCEPTION') || 
                            upperLine.includes('CRITICAL') || upperLine.includes('FATAL')) {
                    className = 'error'
                        } 
                        // Success detection - for AI operations (ChatGPT, Claude, API calls, responses)
                        else if (upperLine.includes('CHATGPT') || upperLine.includes('CLAUDE') ||
                                upperLine.includes('API') || upperLine.includes('RESPONSE') ||
                                upperLine.includes('COMPLETE') || upperLine.includes('SUCCESS') ||
                                upperLine.includes('GENERATED') || upperLine.includes('REPLY') ||
                                line.includes('✅') || upperLine.includes('SUCCEEDED')) {
                            className = 'success'
                        }
                        // Other classifications
                        else if (line.includes('Refined Mode')) {
                    className = 'refined'
                } else if (line.includes('ChatGPT') || line.includes('chatgpt')) {
                    className = 'chatgpt'
                } else if (line.includes('Claude') || line.includes('claude')) {
                    className = 'claude'
                }
                
                // Extract timestamp if present
                const timestampMatch = line.match(/\[(\d{4}-\d{2}-\d{2}T[\d:.]+\d+Z)\]/)
                        let timestamp = ''
                        let logMessage = line
                        
                        if (timestampMatch) {
                            const date = new Date(timestampMatch[1])
                            const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                            const month = months[date.getMonth()]
                            const day = String(date.getDate()).padStart(2, '0')
                            const year = date.getFullYear()
                            const hours = String(date.getHours()).padStart(2, '0')
                            const minutes = String(date.getMinutes()).padStart(2, '0')
                            const seconds = String(date.getSeconds()).padStart(2, '0')
                            const milliseconds = String(date.getMilliseconds()).padStart(3, '0')
                            timestamp = `${month} ${day}, ${year} ${hours}:${minutes}:${seconds}:${milliseconds}`
                            logMessage = line.replace(/\[\d{4}-\d{2}-\d{2}T[\d:.]+\d+Z\]/, '').trim()
                        } else {
                            timestamp = new Date().toLocaleString()
                        }
                        
                        return `<tr class="log-row ${className}" data-message="${logMessage.replace(/"/g, '&quot;').toLowerCase()}">
                            <td class="time-cell">${timestamp}</td>
                            <td class="message-cell">${logMessage.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</td>
                        </tr>`
                    }).join('')}
                </tbody>
            </table>
            ` : `
            <div class="empty-state">
                <div class="empty-state-icon">📝</div>
                <h3>No logs yet</h3>
                <p>Logs will appear here as the server processes requests</p>
            </div>
            `}
        </div>
    </div>
    
    <script>
        let autoRefreshInterval = null;
        let isAutoRefreshing = false;
        let lastLogCount = ${logCount};
        let lastModified = null;
        let isUserScrolling = false;
        let scrollPosition = 0;
        let wasAtBottom = true;
        let previousErrorCount = 0;
        let previousLogCount = ${logCount};
        
        // Initialize error count on page load - match the same detection logic as API
        const initialLogs = ${JSON.stringify(recentLogs.map(line => {
            let className = '';
            const upperLine = line.toUpperCase();
            
            // Extract timestamp
            const timestampMatch = line.match(/\[(\d{4}-\d{2}-\d{2}T[\d:.]+\d+Z)\]/);
            const timestamp = timestampMatch ? timestampMatch[1] : '';
            
            // Error detection - only for actual errors
            if (upperLine.includes('ERROR') || upperLine.includes('❌') || 
                upperLine.includes('FAILED') || upperLine.includes('EXCEPTION') || 
                upperLine.includes('CRITICAL') || upperLine.includes('FATAL')) {
                className = 'error';
            } 
            // Success detection - for AI operations (ChatGPT, Claude, API calls, responses)
            else if (upperLine.includes('CHATGPT') || upperLine.includes('CLAUDE') ||
                    upperLine.includes('API') || upperLine.includes('RESPONSE') ||
                    upperLine.includes('COMPLETE') || upperLine.includes('SUCCESS') ||
                    upperLine.includes('GENERATED') || upperLine.includes('REPLY') ||
                    line.includes('✅') || upperLine.includes('SUCCEEDED')) {
                className = 'success';
            }
            
            return { line, className, raw: line, timestamp: timestamp };
        }))};
        previousErrorCount = initialLogs.filter(log => log.className === 'error').length;
        console.log('Initialized error count:', previousErrorCount, 'from', initialLogs.length, 'logs');
        
        // Initial chart render
        if (initialLogs.length > 0) {
            setTimeout(() => {
                console.log('Rendering initial chart with', initialLogs.length, 'logs');
                renderActivityChart(initialLogs);
            }, 200);
        }
        
        function playErrorSound() {
            try {
                // Create alarm sound using Web Audio API
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.frequency.value = 800;
                oscillator.type = 'sine';
                gainNode.gain.setValueAtTime(0.7, audioContext.currentTime);
                gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
                
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.5);
            } catch (e) {
                console.log('Could not play error sound:', e);
            }
        }
        
        function playActivitySound() {
            try {
                // Create subtle notification sound
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.frequency.value = 600;
                oscillator.type = 'sine';
                gainNode.gain.setValueAtTime(0.2, audioContext.currentTime);
                gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.2);
                
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.2);
            } catch (e) {
                console.log('Could not play activity sound:', e);
            }
        }
        
        function showErrorAlert() {
            const alert = document.getElementById('errorAlert');
            if (alert) {
                alert.classList.add('show');
                playErrorSound();
                setTimeout(() => {
                    alert.classList.remove('show');
                }, 5000);
            }
        }
        
        function showActivityIndicator() {
            const indicator = document.getElementById('activityIndicator');
            if (indicator) {
                indicator.classList.add('show');
                playActivitySound();
                setTimeout(() => {
                    indicator.classList.remove('show');
                }, 2000);
            }
        }
        
        let previousErrorCount = 0;
        let previousLogCount = ${logCount};
        
        // Initialize error count on page load - count errors in initial logs
        const initialLogs = ${JSON.stringify(recentLogs.map(line => {
            const upperLine = line.toUpperCase();
            return {
                line: line,
                className: (upperLine.includes('ERROR') || upperLine.includes('❌') || 
                           upperLine.includes('FAILED') || upperLine.includes('EXCEPTION') || 
                           upperLine.includes('CRITICAL') || upperLine.includes('FATAL')) ? 'error' : ''
            };
        }))};
        previousErrorCount = initialLogs.filter(log => log.className === 'error').length;
        
        function playErrorSound() {
            try {
                // Create alarm sound using Web Audio API
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                
                // Play a sequence of beeps for alarm effect
                [800, 600, 800].forEach((freq, index) => {
                    setTimeout(() => {
                        const oscillator = audioContext.createOscillator();
                        const gainNode = audioContext.createGain();
                        
                        oscillator.connect(gainNode);
                        gainNode.connect(audioContext.destination);
                        
                        oscillator.frequency.value = freq;
                        oscillator.type = 'sine';
                        gainNode.gain.setValueAtTime(0.6, audioContext.currentTime);
                        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
                        
                        oscillator.start(audioContext.currentTime);
                        oscillator.stop(audioContext.currentTime + 0.3);
                    }, index * 150);
                });
            } catch (e) {
                console.log('Could not play error sound:', e);
            }
        }
        
        function playActivitySound() {
            try {
                // Create subtle notification sound
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.frequency.value = 600;
                oscillator.type = 'sine';
                gainNode.gain.setValueAtTime(0.2, audioContext.currentTime);
                gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.15);
                
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.15);
            } catch (e) {
                console.log('Could not play activity sound:', e);
            }
        }
        
        function showErrorAlert() {
            const alert = document.getElementById('errorAlert');
            if (alert) {
                alert.classList.add('show');
                playErrorSound();
                setTimeout(() => {
                    alert.classList.remove('show');
                }, 5000);
            }
        }
        
        function showActivityIndicator() {
            const indicator = document.getElementById('activityIndicator');
            if (indicator) {
                indicator.classList.add('show');
                playActivitySound();
                setTimeout(() => {
                    indicator.classList.remove('show');
                }, 2000);
            }
        }
        
        function renderActivityChart(logs) {
            const canvas = document.getElementById('activityChart');
            if (!canvas) {
                console.log('Chart canvas not found');
                return;
            }
            
            // Set canvas size
            const container = canvas.parentElement;
            const containerWidth = container ? container.clientWidth : 800;
            canvas.width = containerWidth;
            canvas.height = 200;
            
            const ctx = canvas.getContext('2d');
            const width = canvas.width;
            const height = canvas.height;
            
            // Clear canvas and draw background
            ctx.fillStyle = '#0f172a';
            ctx.fillRect(0, 0, width, height);
            
            // Group logs by hour
            const now = new Date();
            const hours = [];
            const hourData = { info: [], success: [], error: [] };
            
            // Get last 24 hours
            for (let i = 23; i >= 0; i--) {
                const hour = new Date(now);
                hour.setHours(hour.getHours() - i);
                hour.setMinutes(0, 0, 0);
                hours.push(hour);
                hourData.info.push(0);
                hourData.success.push(0);
                hourData.error.push(0);
            }
            
            // Count logs per hour
            logs.forEach(log => {
                // Try to get timestamp from log object
                let logTimestamp = log.timestamp || log.raw || '';
                
                // If no timestamp in log object, try to extract from raw line
                if (!logTimestamp && log.raw) {
                    const timestampMatch = log.raw.match(/\[(\d{4}-\d{2}-\d{2}T[\d:.]+\d+Z)\]/);
                    if (timestampMatch) {
                        logTimestamp = timestampMatch[1];
                    }
                }
                
                // If still no timestamp, assign to current hour (for recent logs)
                if (!logTimestamp) {
                    const currentHour = new Date(now);
                    currentHour.setMinutes(0, 0, 0);
                    currentHour.setSeconds(0, 0);
                    logTimestamp = currentHour.toISOString();
                }
                
                try {
                    const logDate = new Date(logTimestamp);
                    if (isNaN(logDate.getTime())) {
                        return;
                    }
                    
                    // Find which hour this log belongs to
                    const logHour = new Date(logDate);
                    logHour.setMinutes(0, 0, 0);
                    logHour.setSeconds(0, 0);
                    
                    const hourIndex = hours.findIndex(h => {
                        return h.getTime() === logHour.getTime();
                    });
                    
                    // If exact match not found, find closest hour within last 24 hours
                    if (hourIndex < 0) {
                        const timeDiff = logDate.getTime() - now.getTime();
                        const hoursDiff = Math.floor(timeDiff / (1000 * 60 * 60));
                        if (hoursDiff >= -23 && hoursDiff <= 0) {
                            const idx = 23 + hoursDiff;
                            if (idx >= 0 && idx < 24) {
                                if (log.className === 'error') {
                                    hourData.error[idx]++;
                                } else if (log.className === 'success') {
                                    hourData.success[idx]++;
                                } else {
                                    hourData.info[idx]++;
                                }
                            }
                        }
                    } else {
                        if (log.className === 'error') {
                            hourData.error[hourIndex]++;
                        } else if (log.className === 'success') {
                            hourData.success[hourIndex]++;
                        } else {
                            hourData.info[hourIndex]++;
                        }
                    }
                } catch (e) {
                    console.log('Error processing log timestamp:', e);
                }
            });
            
            // Find max count for scaling
            const maxCount = Math.max(
                ...hourData.info,
                ...hourData.success,
                ...hourData.error,
                1
            );
            
            const barWidth = Math.max(width / 24, 5);
            const padding = 1;
            
            // Draw axis line
            ctx.strokeStyle = '#334155';
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(0, height - 20);
            ctx.lineTo(width, height - 20);
            ctx.stroke();
            
            // Draw bars
            hours.forEach((hour, index) => {
                const x = index * barWidth;
                const infoCount = hourData.info[index];
                const successCount = hourData.success[index];
                const errorCount = hourData.error[index];
                
                const infoHeight = maxCount > 0 ? (infoCount / maxCount) * (height - 40) : 0;
                const successHeight = maxCount > 0 ? (successCount / maxCount) * (height - 40) : 0;
                const errorHeight = maxCount > 0 ? (errorCount / maxCount) * (height - 40) : 0;
                
                let currentY = height - 20;
                
                // Draw info (blue) at bottom
                if (infoCount > 0) {
                    ctx.fillStyle = '#3b82f6';
                    ctx.fillRect(x + padding, currentY - infoHeight, barWidth - padding * 2, infoHeight);
                    currentY -= infoHeight;
                }
                
                // Draw success (green) on top of info
                if (successCount > 0) {
                    ctx.fillStyle = '#10b981';
                    ctx.fillRect(x + padding, currentY - successHeight, barWidth - padding * 2, successHeight);
                    currentY -= successHeight;
                }
                
                // Draw error (red) on top
                if (errorCount > 0) {
                    ctx.fillStyle = '#ef4444';
                    ctx.fillRect(x + padding, currentY - errorHeight, barWidth - padding * 2, errorHeight);
                }
                
                // Draw hour labels
                if (index % 3 === 0 || index === 23) {
                    ctx.fillStyle = '#94a3b8';
                    ctx.font = '11px monospace';
                    ctx.textAlign = 'center';
                    ctx.fillText(
                        hour.getHours().toString().padStart(2, '0') + ':00',
                        x + barWidth / 2,
                        height - 5
                    );
                }
            });
            
            console.log('Chart rendered with', logs.length, 'logs');
        }
        
        function renderLogs(logs) {
            const container = document.getElementById('logContainer');
            const currentScroll = container.scrollTop;
            const maxScroll = container.scrollHeight - container.clientHeight;
            wasAtBottom = maxScroll - currentScroll < 100; // Within 100px of bottom
            
            // Update activity chart
            renderActivityChart(logs);
            
            // Count errors
            const errorCount = logs.filter(log => log.className === 'error').length;
            const hasNewErrors = errorCount > previousErrorCount;
            const hasNewLogs = logs.length > previousLogCount;
            
            // Debug logging (can be removed later)
            console.log('Error detection:', {
                errorCount,
                previousErrorCount,
                hasNewErrors,
                logCount: logs.length,
                previousLogCount,
                hasNewLogs
            });
            
            // Show error alert if new errors detected
            if (hasNewErrors && previousErrorCount >= 0) {
                console.log('Showing error alert!');
                showErrorAlert();
            }
            
            // Show activity indicator if new logs (but not errors, to avoid double alerts)
            if (hasNewLogs && !hasNewErrors && previousLogCount >= 0) {
                console.log('Showing activity indicator!');
                showActivityIndicator();
            }
            
            // Update counts for next comparison
            previousErrorCount = errorCount;
            previousLogCount = logs.length;
            
            // Build HTML for table
            const tbody = document.getElementById('logTableBody');
            if (!tbody || !container.querySelector('.log-table')) {
                // If table doesn't exist, create it
                let html = '';
                if (logs.length === 0) {
                    html = '<div class="empty-state"><div class="empty-state-icon">📝</div><h3>No logs yet</h3><p>Logs will appear here as the server processes requests</p></div>';
                    container.innerHTML = html;
                } else {
                    html = '<table class="log-table"><thead><tr><th class="time-column">Time</th><th class="message-column">Message</th></tr></thead><tbody id="logTableBody">';
                    logs.forEach(log => {
                        html += buildLogRow(log);
                    });
                    html += '</tbody></table>';
                    container.innerHTML = html;
                }
            } else {
                // Update existing table
                const newTbody = document.getElementById('logTableBody');
                if (newTbody) {
                    newTbody.innerHTML = logs.map(log => buildLogRow(log)).join('');
                }
            }
            
            // Apply search filter if active
            applySearchFilter();
            
            // Restore scroll position or scroll to bottom if user was at bottom
            if (wasAtBottom) {
                setTimeout(() => {
                    container.scrollTop = container.scrollHeight;
                }, 10);
            } else {
                container.scrollTop = currentScroll;
            }
        }
        
        function buildLogRow(log) {
            const className = log.className || '';
            const timestamp = log.timestamp || '';
            const message = log.line || log.raw || '';
            
            let timeDisplay = '';
            if (timestamp) {
                try {
                    const date = new Date(timestamp);
                    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                    const month = months[date.getMonth()];
                    const day = String(date.getDate()).padStart(2, '0');
                    const year = date.getFullYear();
                    const hours = String(date.getHours()).padStart(2, '0');
                    const minutes = String(date.getMinutes()).padStart(2, '0');
                    const seconds = String(date.getSeconds()).padStart(2, '0');
                    const milliseconds = String(date.getMilliseconds()).padStart(3, '0');
                    timeDisplay = month + ' ' + day + ', ' + year + ' ' + hours + ':' + minutes + ':' + seconds + ':' + milliseconds;
                } catch (e) {
                    timeDisplay = timestamp;
                }
            } else {
                timeDisplay = new Date().toLocaleString();
            }
            
            const escapedMessage = message.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
            
            return '<tr class="log-row ' + className + '" data-message="' + escapedMessage.toLowerCase() + '"><td class="time-cell">' + timeDisplay + '</td><td class="message-cell">' + escapedMessage + '</td></tr>';
        }
        
        function applySearchFilter() {
            const searchInput = document.getElementById('searchInput');
            const searchTerm = searchInput ? searchInput.value.toLowerCase().trim() : '';
            const rows = document.querySelectorAll('#logTableBody tr.log-row');
            
            if (!searchTerm) {
                rows.forEach(function(row) { row.classList.remove('hidden'); });
                return;
            }
            
            rows.forEach(function(row) {
                const message = row.getAttribute('data-message') || '';
                if (message.includes(searchTerm)) {
                    row.classList.remove('hidden');
                } else {
                    row.classList.add('hidden');
                }
            });
        }
        
        async function fetchLogs(forceUpdate = false) {
            try {
                const response = await fetch('/api/logs', {
                    credentials: 'include',
                    headers: {
                        'Accept': 'application/json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error('HTTP error! status: ' + response.status);
                }
                
                const data = await response.json();
                
                if (data.success) {
                    const hasNewLogs = forceUpdate || data.count !== lastLogCount || (data.lastModified && data.lastModified !== lastModified);
                    
                    if (hasNewLogs || forceUpdate) {
                        lastLogCount = data.count;
                        lastModified = data.lastModified;
                        renderLogs(data.logs);
                        
                        // Update chart with new data
                        if (data.logs && data.logs.length > 0) {
                            setTimeout(() => {
                                console.log('Updating chart with', data.logs.length, 'logs');
                                renderActivityChart(data.logs);
                            }, 50);
                        }
                        
                        // Show visual indicator if new logs arrived
                        if (isAutoRefreshing && wasAtBottom && !forceUpdate) {
                            showNewLogIndicator();
                        }
                    }
                    
                    return data;
                } else {
                    console.error('Error fetching logs:', data.error);
                    if (forceUpdate) {
                        alert('Error fetching logs: ' + (data.error || 'Unknown error'));
                    }
                }
            } catch (error) {
                console.error('Error fetching logs:', error);
                if (forceUpdate) {
                    alert('Error fetching logs: ' + error.message);
                }
            }
        }
        
        function refreshLogs() {
            console.log('Refresh button clicked');
            const btn = document.getElementById('refreshBtn');
            if (btn) {
                btn.textContent = '🔄 Refreshing...';
                btn.disabled = true;
            }
            
            fetchLogs(true).then(() => {
                if (btn) {
                    btn.textContent = '🔄 Refresh';
                    btn.disabled = false;
                }
            }).catch((error) => {
                console.error('Error refreshing logs:', error);
                if (btn) {
                    btn.textContent = '🔄 Refresh';
                    btn.disabled = false;
                }
            });
        }
        
        // Test functions
        async function testError() {
            console.log('=== TEST ERROR BUTTON CLICKED ===');
            const btn = document.getElementById('testErrorBtn');
            if (!btn) {
                console.error('Test Error button not found!');
                alert('Test Error button not found! Check console.');
                return;
            }
            
            btn.disabled = true;
            btn.textContent = '⚠️ Testing...';
            
            try {
                console.log('Sending POST request to /api/logs/test...');
                const response = await fetch('/api/logs/test', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ type: 'error' })
                });
                
                console.log('Response received:', {
                    status: response.status,
                    statusText: response.statusText,
                    ok: response.ok,
                    headers: Object.fromEntries(response.headers.entries())
                });
                
                if (!response.ok) {
                    let errorText = '';
                    try {
                        errorText = await response.text();
                        console.error('Response error text:', errorText);
                    } catch (e) {
                        console.error('Could not read error response:', e);
                    }
                    alert('Error: ' + response.status + ' ' + response.statusText + (errorText ? '\n\n' + errorText : ''));
                    btn.disabled = false;
                    btn.textContent = '⚠️ Test Error';
                    return;
                }
                
                let data;
                try {
                    data = await response.json();
                    console.log('Response JSON data:', data);
                } catch (e) {
                    console.error('Could not parse JSON response:', e);
                    alert('Error: Could not parse response. Check console.');
                    btn.disabled = false;
                    btn.textContent = '⚠️ Test Error';
                    return;
                }
                
                if (data.success) {
                    console.log('✅ Test error generated successfully!');
                    console.log('Waiting 800ms for log file to be written...');
                    
                    // Wait a bit for log file to be written, then refresh
                    setTimeout(() => {
                        console.log('Refreshing logs...');
                        refreshLogs(true);
                        
                        // Force show error alert after refresh
                        setTimeout(() => {
                            console.log('Attempting to show error alert...');
                            const errorAlert = document.getElementById('errorAlert');
                            if (errorAlert) {
                                console.log('✅ Error alert element found, showing it...');
                                errorAlert.classList.add('show');
                                playErrorSound();
                                setTimeout(() => {
                                    errorAlert.classList.remove('show');
                                }, 5000);
                            } else {
                                console.error('❌ Error alert element not found!');
                            }
                        }, 1000);
                    }, 800);
                } else {
                    alert('Error: ' + (data.error || 'Failed to generate test error'));
                    btn.disabled = false;
                    btn.textContent = '⚠️ Test Error';
                }
            } catch (error) {
                console.error('❌ Exception in testError:', error);
                console.error('Error stack:', error.stack);
                alert('Error: ' + error.message + '\n\nCheck console (F12) for details.');
                btn.disabled = false;
                btn.textContent = '⚠️ Test Error';
            }
        }
        
        async function testActivity() {
            const btn = document.getElementById('testActivityBtn');
            if (btn) {
                btn.disabled = true;
                btn.textContent = '📝 Testing...';
            }
            try {
                const response = await fetch('/api/logs/test', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ type: 'activity' })
                });
                const data = await response.json();
                if (data.success) {
                    alert('Test activity generated! Check the logs below. You should see a green activity indicator and hear a subtle sound.');
                    setTimeout(() => refreshLogs(true), 500);
                } else {
                    alert('Error: ' + (data.error || 'Failed to generate test activity'));
                }
            } catch (error) {
                alert('Error: ' + error.message);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = '📝 Test Activity';
                }
            }
        }
        
        // Search functionality
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', applySearchFilter);
            searchInput.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    searchInput.value = '';
                    applySearchFilter();
                }
            });
        }
        
        // Search functionality
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', applySearchFilter);
            searchInput.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') {
                    searchInput.value = '';
                    applySearchFilter();
                }
            });
        }
        
        // Make functions globally accessible (for onclick handlers)
        window.refreshLogs = refreshLogs;
        window.toggleAutoRefresh = toggleAutoRefresh;
        window.clearLogs = clearLogs;
        window.scrollToTop = scrollToTop;
        window.scrollToBottom = scrollToBottom;
        window.testError = testError;
        window.testActivity = testActivity;
        
        // Initial render on page load
        if (typeof initialLogs !== 'undefined' && initialLogs.length > 0) {
            renderActivityChart(initialLogs);
        }
        
        // Resize chart on window resize
        window.addEventListener('resize', function() {
            const logs = document.querySelectorAll('#logTableBody tr.log-row');
            if (logs.length > 0) {
                const logData = Array.from(logs).map(row => {
                    const className = row.className.includes('error') ? 'error' : 
                                     row.className.includes('success') ? 'success' : '';
                    const timeCell = row.querySelector('.time-cell');
                    const messageCell = row.querySelector('.message-cell');
                    return {
                        className: className,
                        timestamp: timeCell ? timeCell.textContent : '',
                        raw: messageCell ? messageCell.textContent : ''
                    };
                });
                renderActivityChart(logData);
            }
        });
        
        // Debug: Verify functions are available
        console.log('Test functions available:', {
            testError: typeof window.testError,
            testActivity: typeof window.testActivity
        });
        
        // Attach event listeners when DOM is ready (backup for onclick)
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', attachEventListeners);
        } else {
            attachEventListeners();
        }
        
        function attachEventListeners() {
            const refreshBtn = document.getElementById('refreshBtn');
            const autoRefreshBtn = document.getElementById('autoRefreshBtn');
            const clearBtn = document.getElementById('clearBtn');
            const topBtn = document.getElementById('topBtn');
            const bottomBtn = document.getElementById('bottomBtn');
            
            if (refreshBtn) {
                refreshBtn.onclick = refreshLogs;
                refreshBtn.addEventListener('click', refreshLogs);
            }
            if (autoRefreshBtn) {
                autoRefreshBtn.onclick = toggleAutoRefresh;
                autoRefreshBtn.addEventListener('click', toggleAutoRefresh);
            }
            if (clearBtn) {
                clearBtn.onclick = clearLogs;
                clearBtn.addEventListener('click', clearLogs);
            }
            if (topBtn) {
                topBtn.onclick = scrollToTop;
                topBtn.addEventListener('click', scrollToTop);
            }
            if (bottomBtn) {
                bottomBtn.onclick = scrollToBottom;
                bottomBtn.addEventListener('click', scrollToBottom);
            }
        }
        
        function toggleAutoRefresh() {
            console.log('Toggle auto-refresh clicked, current state:', isAutoRefreshing);
            const btn = document.getElementById('autoRefreshBtn');
            const status = document.getElementById('autoRefreshStatus');
            
            if (!btn) {
                console.error('Auto-refresh button not found');
                return;
            }
            
            if (isAutoRefreshing) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
                isAutoRefreshing = false;
                btn.textContent = '▶️ Auto-Refresh';
                if (status) status.textContent = 'Auto-refresh: OFF';
                btn.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
                console.log('Auto-refresh stopped');
            } else {
                // Smart auto-refresh: Check every 2 seconds and only update if new logs detected
                autoRefreshInterval = setInterval(async () => {
                    await fetchLogs(false);
                }, 2000); // Check every 2 seconds
                isAutoRefreshing = true;
                btn.textContent = '⏸️ Auto-Refresh';
                if (status) status.textContent = 'Auto-refresh: ON (2s)';
                btn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
                console.log('Auto-refresh started');
            }
        }
        
        function showNewLogIndicator() {
            // Subtle flash animation when new logs arrive
            const container = document.getElementById('logContainer');
            container.style.transition = 'background-color 0.3s';
            container.style.backgroundColor = 'rgba(102, 126, 234, 0.1)';
            setTimeout(() => {
                container.style.backgroundColor = '#0f172a';
            }, 300);
        }
        
        function clearLogs() {
            if (confirm('This will clear the log file. Continue?')) {
                fetch('/api/logs/clear', {
                    method: 'POST',
                    credentials: 'include'
                }).then(() => {
                    lastLogCount = 0;
                    lastModified = null;
                    fetchLogs(true);
                }).catch(err => {
                    alert('Error clearing logs: ' + err.message);
                });
            }
        }
        
        function scrollToTop() {
            const container = document.getElementById('logContainer');
            if (container) {
                container.scrollTop = 0;
                wasAtBottom = false;
            }
        }
        
        function scrollToBottom() {
            const container = document.getElementById('logContainer');
            if (container) {
                container.scrollTop = container.scrollHeight;
                wasAtBottom = true;
            }
        }
        
        // Track scroll position
        const logContainer = document.getElementById('logContainer');
        if (logContainer) {
            logContainer.addEventListener('scroll', () => {
                scrollPosition = logContainer.scrollTop;
                const maxScroll = logContainer.scrollHeight - logContainer.clientHeight;
                wasAtBottom = maxScroll - logContainer.scrollTop < 100;
            });
        }
        
        // Initialize on page load
        window.addEventListener('load', () => {
            setTimeout(() => {
                scrollToBottom();
                // Initialize last log count
                lastLogCount = ${logCount};
            }, 100);
        });
        
        // Check for new logs periodically even when auto-refresh is off (less frequent)
        setInterval(async () => {
            if (!isAutoRefreshing) {
                await fetchLogs(false);
            }
        }, 10000); // Check every 10 seconds when auto-refresh is off
    </script>
</body>
</html>
        `)
    } catch (error) {
        res.status(500).send(`
            <html>
                <body style="font-family: sans-serif; padding: 40px; text-align: center;">
                    <h1>Error loading logs</h1>
                    <p>${error.message}</p>
                    <a href="/" style="color: #667eea;">← Back to Status</a>
                </body>
            </html>
        `)
    }
})

// API endpoint to get logs (for AJAX refresh)
app.get("/api/logs", requireDeveloperAuth, (req, res) => {
    try {
        let logLines = []
        let lastModified = null
        
        if (existsSync(LOG_FILE)) {
            try {
                const stats = statSync(LOG_FILE)
                lastModified = stats.mtime.getTime()
                const logContent = readFileSync(LOG_FILE, "utf-8")
                logLines = logContent.split('\n').filter(line => line.trim().length > 0)
            } catch (error) {
                return res.status(500).json({ error: `Error reading log file: ${error.message}` })
            }
        }
        
        // Get last 500 lines (most recent)
        const recentLogs = logLines.slice(-500).reverse() // Newest first
        
        // Format logs for JSON response
        const formattedLogs = recentLogs.map(line => {
            let className = ''
            const upperLine = line.toUpperCase()
            
            // Error detection - only for actual errors
            if (upperLine.includes('ERROR') || upperLine.includes('❌') || 
                upperLine.includes('FAILED') || upperLine.includes('EXCEPTION') || 
                upperLine.includes('CRITICAL') || upperLine.includes('FATAL')) {
                className = 'error'
            } 
            // Success detection - for AI operations (ChatGPT, Claude, API calls, responses)
            else if (upperLine.includes('CHATGPT') || upperLine.includes('CLAUDE') ||
                    upperLine.includes('API') || upperLine.includes('RESPONSE') ||
                    upperLine.includes('COMPLETE') || upperLine.includes('SUCCESS') ||
                    upperLine.includes('GENERATED') || upperLine.includes('REPLY') ||
                    line.includes('✅') || upperLine.includes('SUCCEEDED')) {
                className = 'success'
            } 
            // Other classifications
            else if (line.includes('Refined Mode')) {
                className = 'refined'
            } else if (line.includes('ChatGPT') || line.includes('chatgpt')) {
                className = 'chatgpt'
            } else if (line.includes('Claude') || line.includes('claude')) {
                className = 'claude'
            }
            
            // Extract timestamp if present
            const timestampMatch = line.match(/\[(\d{4}-\d{2}-\d{2}T[\d:.]+\d+Z)\]/)
            const timestamp = timestampMatch ? timestampMatch[1] : ''
            const logMessage = timestamp ? line.replace(/\[\d{4}-\d{2}-\d{2}T[\d:.]+\d+Z\]/, '').trim() : line
            
            return {
                line: logMessage,
                timestamp: timestamp,
                className: className,
                raw: line
            }
        })
        
        res.json({
            success: true,
            logs: formattedLogs,
            count: formattedLogs.length,
            lastModified: lastModified
        })
    } catch (error) {
        res.status(500).json({ success: false, error: error.message })
    }
})

// API endpoint to clear logs (optional)
app.post("/api/logs/clear", requireDeveloperAuth, (req, res) => {
    try {
        if (existsSync(LOG_FILE)) {
            writeFileSync(LOG_FILE, "", "utf-8")
            res.json({ success: true, message: "Logs cleared" })
        } else {
            res.json({ success: true, message: "No log file to clear" })
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message })
    }
})

// Test endpoint to generate test logs (for testing alerts and sounds)
app.post("/api/logs/test", requireDeveloperAuth, (req, res) => {
    try {
        console.log('Test endpoint called with body:', req.body);
        const { type = 'error' } = req.body
        
        if (type === 'error') {
            console.log('Generating test error logs...');
            log("TEST ERROR: This is a test error message to verify error alerts and sounds", 'error')
            log("TEST ERROR: Another test error for verification", 'error')
            console.log('Test error logs written to file');
            res.json({ success: true, message: "Test error logs generated. Check the logs page!" })
        } else if (type === 'activity') {
            console.log('Generating test activity logs...');
            log("TEST ACTIVITY: This is a test log entry to verify activity alerts and sounds")
            log("TEST ACTIVITY: Another test log entry")
            console.log('Test activity logs written to file');
            res.json({ success: true, message: "Test activity logs generated. Check the logs page!" })
        } else if (type === 'success') {
            console.log('Generating test success log...');
            log("TEST SUCCESS: This is a test success message ✅")
            console.log('Test success log written to file');
            res.json({ success: true, message: "Test success log generated. Check the logs page!" })
        } else {
            res.status(400).json({ success: false, error: "Invalid type. Use 'error', 'activity', or 'success'" })
        }
    } catch (error) {
        console.error('Error in test endpoint:', error);
        res.status(500).json({ success: false, error: error.message })
    }
})

app.post("/api/claude", async (req, res) => {
    // Check maintenance mode
    const maintenance = loadMaintenanceMode()
    if (maintenance.enabled) {
        res.status(503).json({ 
            error: "AI services are currently under maintenance",
            message: maintenance.message,
            maintenance: true
        })
        return
    }

    if (!anthropicClient) {
        res.status(500).json({ error: "Anthropic API key not configured on the server" })
        return
    }

    const { prompt, system, temperature = 0.7, maxTokens, model } = req.body ?? {}

    if (!prompt || typeof prompt !== "string") {
        res.status(400).json({ error: "Prompt is required" })
        return
    }

    const resolvedModel = model || process.env.ANTHROPIC_MODEL || "claude-3-5-sonnet-20240620"
    const resolvedMaxTokens =
        typeof maxTokens === "number" ? maxTokens : Number(process.env.ANTHROPIC_MAX_TOKENS) || 1024

    try {
        const completion = await anthropicClient.messages.create({
            model: resolvedModel,
            temperature,
            max_tokens: resolvedMaxTokens,
            system,
            messages: [{ role: "user", content: prompt }],
        })

        const reply = completion.content
            ?.map((block) => ("text" in block ? block.text : ""))
            .join("\n")
            .trim()

        res.json({
            reply,
            model: resolvedModel,
        })
    } catch (error) {
        console.error("Anthropic error:", error)
        res.status(500).json({ error: "Anthropic request failed", details: error.message })
    }
})

// In-memory user profiles (in production, use a database)
const userProfiles = new Map()

// Conversation logs storage
const CONVERSATION_LOGS_FILE = join(__dirname, "conversation_logs.json")
const ANALYTICS_FILE = join(__dirname, "analytics.json")
const KNOWLEDGE_BASE_FILE = join(__dirname, "knowledge_base.txt")

// Load knowledge base from file
function loadKnowledgeBase() {
    try {
        if (existsSync(KNOWLEDGE_BASE_FILE)) {
            const knowledgeBase = readFileSync(KNOWLEDGE_BASE_FILE, "utf-8").trim()
            return knowledgeBase
        }
    } catch (error) {
        console.error("Error loading knowledge base:", error)
    }
    return null
}

// Cache knowledge base in memory (reload on server restart)
let cachedKnowledgeBase = loadKnowledgeBase()
if (cachedKnowledgeBase) {
    console.log(`[Knowledge Base] ✅ Loaded ${cachedKnowledgeBase.length} characters from knowledge_base.txt`)
} else {
    console.log(`[Knowledge Base] ⚠️  No knowledge_base.txt found. Create one to add custom training data.`)
}

// API Pricing per 1M tokens (as of 2024)
// OpenAI pricing: https://openai.com/api/pricing/
// Anthropic pricing: https://www.anthropic.com/pricing
const API_PRICING = {
    // OpenAI models (per 1M tokens)
    'gpt-4o': { input: 2.50, output: 10.00 },
    'gpt-4o-mini': { input: 0.15, output: 0.60 },
    'gpt-4-turbo': { input: 10.00, output: 30.00 },
    'gpt-4': { input: 30.00, output: 60.00 },
    'gpt-3.5-turbo': { input: 0.50, output: 1.50 },
    // Anthropic models (per 1M tokens)
    'claude-3-5-sonnet-20240620': { input: 3.00, output: 15.00 },
    'claude-3-5-haiku-20241022': { input: 1.00, output: 5.00 },
    'claude-3-haiku-20240307': { input: 0.25, output: 1.25 },
    'claude-3-opus-20240229': { input: 15.00, output: 75.00 },
    'claude-3-sonnet-20240229': { input: 3.00, output: 15.00 },
    // Default fallback pricing
    'default-openai': { input: 0.15, output: 0.60 }, // gpt-4o-mini default
    'default-anthropic': { input: 0.25, output: 1.25 }, // haiku default
}

// Calculate cost from tokens
function calculateTokenCost(model, inputTokens, outputTokens) {
    const pricing = API_PRICING[model] || 
                   (model.includes('gpt') || model.includes('openai') ? API_PRICING['default-openai'] : API_PRICING['default-anthropic'])
    
    const inputCost = (inputTokens / 1000000) * pricing.input
    const outputCost = (outputTokens / 1000000) * pricing.output
    return inputCost + outputCost
}

// Get model name from full model string
function getModelName(modelString) {
    if (!modelString) return 'unknown'
    // Extract base model name (e.g., "gpt-4o-mini" from "gpt-4o-mini-2024-08-06")
    const match = modelString.match(/(gpt-[0-9a-z-]+|claude-[0-9a-z-]+)/i)
    return match ? match[1] : modelString.split('-')[0] + '-' + modelString.split('-')[1]
}

// Load conversation logs
function loadConversationLogs() {
    try {
        if (existsSync(CONVERSATION_LOGS_FILE)) {
            const data = readFileSync(CONVERSATION_LOGS_FILE, "utf-8")
            return JSON.parse(data)
        }
    } catch (error) {
        console.error("Error loading conversation logs:", error)
    }
    return []
}

// Save conversation log
function saveConversationLog(logEntry) {
    try {
        const logs = loadConversationLogs()
        logs.push(logEntry)
        // Keep only last 1000 conversations to avoid file size issues
        const trimmedLogs = logs.slice(-1000)
        writeFileSync(CONVERSATION_LOGS_FILE, JSON.stringify(trimmedLogs, null, 2))
    } catch (error) {
        console.error("Error saving conversation log:", error)
    }
}

// Load analytics
function loadAnalytics() {
    try {
        if (existsSync(ANALYTICS_FILE)) {
            const data = readFileSync(ANALYTICS_FILE, "utf-8")
            return JSON.parse(data)
        }
    } catch (error) {
        console.error("Error loading analytics:", error)
    }
    return {
        totalConversations: 0,
        totalMessages: 0,
        totalTokens: 0,
        totalCost: 0.0,
        openaiCost: 0.0,
        anthropicCost: 0.0,
        averageResponseTime: 0,
        toneAdaptedUsers: [],
        chatgptCalls: 0,
        claudeCalls: 0,
        fusedCalls: 0,
        failedCalls: 0,
        imageGenerations: 0,
        pageScans: 0,
        responseTimes: [],
        toneAdaptationRate: 0,
        lastUpdated: new Date().toISOString()
    }
}

// Update analytics
function updateAnalytics(metrics) {
    try {
        const analytics = loadAnalytics()
        
        analytics.totalConversations += 1
        analytics.totalMessages += metrics.messageCount || 0
        analytics.totalTokens += metrics.tokensUsed || 0
        
        // Calculate and add cost
        if (metrics.cost) {
            analytics.totalCost = (analytics.totalCost || 0) + metrics.cost
        }
        if (metrics.openaiCost) {
            analytics.openaiCost = (analytics.openaiCost || 0) + metrics.openaiCost
        }
        if (metrics.anthropicCost) {
            analytics.anthropicCost = (analytics.anthropicCost || 0) + metrics.anthropicCost
        }
        
        // Update response times
        if (metrics.responseTime) {
            analytics.responseTimes.push(metrics.responseTime)
            // Keep only last 1000 response times
            if (analytics.responseTimes.length > 1000) {
                analytics.responseTimes = analytics.responseTimes.slice(-1000)
            }
            // Calculate average
            const sum = analytics.responseTimes.reduce((a, b) => a + b, 0)
            analytics.averageResponseTime = Math.round(sum / analytics.responseTimes.length)
        }
        
        // Update model call counts
        if (metrics.model === "chatgpt-only") analytics.chatgptCalls += 1
        else if (metrics.model === "claude-only") analytics.claudeCalls += 1
        else if (metrics.model === "lumra-fused") analytics.fusedCalls += 1
        
        if (metrics.failed) analytics.failedCalls += 1
        if (metrics.isImageGeneration) analytics.imageGenerations += 1
        if (metrics.isPageScan) analytics.pageScans += 1
        
        // Update tone adaptation
        if (metrics.toneAdapted) {
            // Ensure toneAdaptedUsers is an array
            if (!Array.isArray(analytics.toneAdaptedUsers)) {
                analytics.toneAdaptedUsers = []
            }
            if (!analytics.toneAdaptedUsers.includes(metrics.userId)) {
                analytics.toneAdaptedUsers.push(metrics.userId)
            }
        }
        
        // Calculate tone adaptation rate
        const uniqueUsers = new Set()
        const logs = loadConversationLogs()
        logs.forEach(log => {
            if (log.userId) uniqueUsers.add(log.userId)
        })
        const usersWithTone = logs.filter(log => log.toneAdapted).map(log => log.userId)
        const uniqueUsersWithTone = new Set(usersWithTone).size
        analytics.toneAdaptationRate = uniqueUsers.size > 0 
            ? Math.round((uniqueUsersWithTone / uniqueUsers.size) * 100) 
            : 0
        
        analytics.lastUpdated = new Date().toISOString()
        
        writeFileSync(ANALYTICS_FILE, JSON.stringify(analytics, null, 2))
    } catch (error) {
        console.error("Error updating analytics:", error)
    }
}

function analyzeToneFromHistory(history) {
    if (!history || history.length === 0) return null
    
    // Extract user messages
    const userMessages = history
        .filter((msg) => msg.role === "user")
        .map((msg) => msg.content)
        .join("\n\n")
    
    if (userMessages.length < 50) return null // Need enough text to analyze
    
    return {
        messageCount: history.filter((msg) => msg.role === "user").length,
        totalLength: userMessages.length,
        sample: userMessages.substring(0, 500), // First 500 chars for analysis
    }
}

async function getAdaptiveSystemPrompt(userId, conversationHistory, providedSystem) {
    const profile = userProfiles.get(userId) || { tone: null, preferences: null, messageCount: 0 }
    const history = conversationHistory || []
    
    // If we have enough history but no tone profile yet, analyze it
    if (history.length >= 3 && !profile.tone) {
        const toneAnalysis = analyzeToneFromHistory(history)
        
        if (toneAnalysis && openaiClient) {
            try {
                // Use AI to analyze user's communication style
                const analysisPrompt = `Analyze the following conversation history from a user. Extract:
1. Communication tone (formal, casual, professional, friendly, technical, etc.)
2. Writing style preferences (concise, detailed, bullet points, paragraphs)
3. Preferred response format
4. Any recurring topics or interests

User messages:
${toneAnalysis.sample}

Provide a concise analysis (2-3 sentences) of the user's communication style:`

                const analysisResponse = await openaiClient.chat.completions.create({
                    model: process.env.OPENAI_MODEL || "gpt-4o-mini",
                    temperature: 0.3,
                    messages: [
                        {
                            role: "system",
                            content: "You are an expert at analyzing communication styles. Be concise and specific.",
                        },
                        { role: "user", content: analysisPrompt },
                    ],
                    max_tokens: 200,
                })

                const toneAnalysisText = analysisResponse.choices[0]?.message?.content?.trim() || ""
                
                // Update user profile
                profile.tone = toneAnalysisText
                profile.messageCount = toneAnalysis.messageCount
                userProfiles.set(userId, profile)
            } catch (error) {
                console.error("Tone analysis error:", error)
            }
        }
    } else if (history.length > profile.messageCount && profile.tone) {
        // Re-analyze periodically if we have significantly more messages
        const toneAnalysis = analyzeToneFromHistory(history)
        if (toneAnalysis && toneAnalysis.messageCount >= profile.messageCount + 5) {
            // Re-analyze every 5 new messages to keep tone profile updated
            profile.messageCount = toneAnalysis.messageCount
            userProfiles.set(userId, profile)
        }
    }
    
    // Build adaptive system prompt
    let adaptiveSystem = providedSystem || ""
    
    // Inject knowledge base if available (optimized: only add if not too long)
    if (cachedKnowledgeBase && cachedKnowledgeBase.length < 3000) {
        // Only inject if knowledge base is reasonable size (prevents slow API calls)
        const knowledgeBaseSection = `\n\n=== KNOWLEDGE BASE (MANDATORY GUIDELINES) ===\n${cachedKnowledgeBase}\n\nCRITICAL: You MUST follow ALL guidelines in the knowledge base above. These are not suggestions - they are mandatory rules for how you must respond. Pay special attention to the "HOMEWORK AND ASSIGNMENT HELP" section - you MUST guide students, never give direct answers.`
        adaptiveSystem = adaptiveSystem ? `${adaptiveSystem}${knowledgeBaseSection}` : knowledgeBaseSection.trim()
    } else if (cachedKnowledgeBase && cachedKnowledgeBase.length >= 3000) {
        // For large knowledge bases, prioritize critical sections
        // Extract homework section first, then add summary of rest
        const homeworkMatch = cachedKnowledgeBase.match(/=== HOMEWORK AND ASSIGNMENT HELP[^=]+===/s)
        const homeworkSection = homeworkMatch ? homeworkMatch[0] : ""
        const restOfKB = cachedKnowledgeBase.replace(/=== HOMEWORK AND ASSIGNMENT HELP[^=]+===/s, "").substring(0, 2000)
        const knowledgeBaseSection = `\n\n=== KNOWLEDGE BASE (MANDATORY GUIDELINES) ===\n${homeworkSection}\n\n${restOfKB}\n\nCRITICAL: You MUST follow ALL guidelines above, especially the homework guidance rules. These are mandatory, not suggestions.`
        adaptiveSystem = adaptiveSystem ? `${adaptiveSystem}${knowledgeBaseSection}` : knowledgeBaseSection.trim()
    }
    
    if (profile.tone) {
        const toneGuidance = `\n\nUser's communication style: ${profile.tone}\nAdapt your responses to match this style while maintaining accuracy and helpfulness.`
        adaptiveSystem = adaptiveSystem ? `${adaptiveSystem}${toneGuidance}` : toneGuidance.trim()
    }
    
    return adaptiveSystem || undefined
}

// Helper function to detect if user wants to generate an image
function isImageGenerationRequest(prompt) {
    const lowerPrompt = prompt.toLowerCase().trim()
    
    // Explicit image generation phrases - must contain both verb AND image noun
    const explicitImagePhrases = [
        "generate an image", "create an image", "make an image", "draw an image",
        "generate a picture", "create a picture", "make a picture", "draw a picture",
        "generate a photo", "create a photo", "make a photo", "draw a photo",
        "generate a drawing", "create a drawing", "make a drawing",
        "show me an image", "show me a picture", "show me a photo",
        "i want an image", "i want a picture", "i want a photo", "i want a drawing",
        "give me an image", "give me a picture", "give me a photo", "give me a drawing",
        "can you create an image", "can you make an image", "can you generate an image", "can you draw an image",
        "can you create a picture", "can you make a picture", "can you generate a picture", "can you draw a picture",
        "please create an image", "please make an image", "please generate an image", "please draw an image",
        "please create a picture", "please make a picture", "please generate a picture", "please draw a picture"
    ]
    
    // Check for explicit image generation phrases
    if (explicitImagePhrases.some(phrase => lowerPrompt.includes(phrase))) {
        return true
    }
    
    // Check for "image of" or "picture of" patterns (but not in questions)
    if (!lowerPrompt.includes("?") && (lowerPrompt.includes("image of") || lowerPrompt.includes("picture of") || lowerPrompt.includes("photo of") || lowerPrompt.includes("drawing of"))) {
        return true
    }
    
    // Only check verbs if they're explicitly paired with image nouns
    const imageVerbs = ["generate", "create", "make", "draw"]
    const imageNouns = ["image", "picture", "photo", "drawing"]
    
    // Check if prompt starts with an image verb followed by an image noun
    const words = lowerPrompt.split(/\s+/)
    for (let i = 0; i < words.length - 1; i++) {
        if (imageVerbs.includes(words[i]) && imageNouns.some(noun => words.slice(i + 1, i + 4).join(" ").includes(noun))) {
            return true
        }
    }
    
    return false
}

// Helper to parse multipart form data manually (since we're not using multer)
async function parseMultipartFormData(req) {
    return new Promise((resolve, reject) => {
        if (req.headers['content-type']?.includes('multipart/form-data')) {
            // For now, we'll handle this in the route
            // This is a simplified version - in production, use multer
            resolve(null)
        } else {
            resolve(req.body)
        }
    })
}

app.post("/api/fuse", authenticateToken, aiLimiter, async (req, res) => {
    // Check maintenance mode
    const maintenance = loadMaintenanceMode()
    if (maintenance.enabled) {
        console.log(`[Maintenance Mode] Request blocked for user: ${req.body?.userId || 'unknown'}`)
        res.status(503).json({ 
            error: "AI services are currently under maintenance",
            message: maintenance.message,
            maintenance: true,
            code: "MAINTENANCE_MODE"
        })
        return
    }

    if (!openaiClient || !anthropicClient) {
        res.status(500).json({ error: "Both OpenAI and Anthropic API keys must be configured" })
        return
    }

    // Handle JSON request (with optional base64-encoded files)
    const body = req.body ?? {}
    const prompt = body.prompt
    const system = body.system
    const conversationHistory = body.conversationHistory || []
    const userId = body.userId
    const mode = body.mode || 'quick'
    const files = body.files || [] // Array of { name, type, data: base64 }
    
    // CRITICAL: Auto-upload PDFs and documents sent via chat to document storage
    // Use authenticated user email, not random userId
    const chatUserIdentifier = req.user?.email || req.user?.id || userId || "anonymous"
    
    // DEBUG: Log all files received
    if (files.length > 0) {
        log(`[RAG] 🔍 Received ${files.length} file(s) - checking for documents...`)
        files.forEach((f, idx) => {
            log(`[RAG]   File ${idx + 1}: name="${f.name || 'unnamed'}", type="${f.type || 'unknown'}", dataLength=${f.data?.length || 0}, hasData=${!!f.data}`)
        })
    } else {
        log(`[RAG] ℹ️  No files received in request body`)
    }
    
    const documentFiles = files.filter((f) => {
        const type = f.type?.toLowerCase() || ''
        const name = f.name?.toLowerCase() || ''
        const isDocument = 
               // PDFs
               type.includes('pdf') || name.endsWith('.pdf') ||
               // Word documents
               type.includes('wordprocessingml') || type.includes('msword') ||
               name.endsWith('.docx') || name.endsWith('.doc') ||
               // Excel files
               type.includes('spreadsheetml') || type.includes('ms-excel') ||
               name.endsWith('.xlsx') || name.endsWith('.xls') ||
               // PowerPoint
               type.includes('presentationml') || type.includes('ms-powerpoint') ||
               name.endsWith('.pptx') || name.endsWith('.ppt') ||
               // Text files
               type.includes('text/') || type.includes('text/plain') ||
               name.endsWith('.txt') || name.endsWith('.md') || name.endsWith('.rtf') ||
               // Other document formats
               name.endsWith('.json') || name.endsWith('.csv') || name.endsWith('.xml') ||
               name.endsWith('.html') || name.endsWith('.htm') || name.endsWith('.yaml') ||
               name.endsWith('.yml') || type.includes('document')
        if (isDocument) {
            log(`[RAG] ✅ Document detected: ${f.name} (type: ${f.type || 'unknown'})`)
        }
        return isDocument
    })
    
    log(`[RAG] 📊 Document detection: ${documentFiles.length} document(s) found out of ${files.length} file(s)`)
    
    // Check RAG availability with detailed diagnostics
    let ragAvailable = isRAGAvailable()
    let vectorAvailable = false
    let openaiAvailableInRAG = false
    
    try {
        const { isVectorDBAvailable } = await import("./vectorDB.js")
        vectorAvailable = isVectorDBAvailable()
        // Check if OpenAI client is set in RAG module
        const { isRAGAvailable: checkRAG } = await import("./rag.js")
        openaiAvailableInRAG = checkRAG() || false
    } catch (importError) {
        log(`[RAG] ⚠️  Error checking RAG status: ${importError.message}`, "error")
    }
    
    log(`[RAG] 🔍 RAG Diagnostics: ragAvailable=${ragAvailable}, vectorDB=${vectorAvailable}, openaiClient=${openaiClient !== null}, openaiInRAG=${openaiAvailableInRAG}`)
    
    // CRITICAL FIX: If RAG is not available but we have OpenAI client, force-initialize it
    if (documentFiles.length > 0 && !ragAvailable && openaiClient) {
        log(`[RAG] 🔧 RAG not available but OpenAI client exists - force-initializing RAG...`)
        try {
            log(`[RAG] 🔍 OpenAI client status: ${openaiClient ? 'exists' : 'null'}`)
            const initResult = await initializeRAG(openaiClient)
            log(`[RAG] 🔍 initializeRAG returned: ${initResult}`)
            if (initResult) {
                log(`[RAG] ✅ Force-initialization successful!`)
                ragAvailable = isRAGAvailable()
                log(`[RAG] 🔍 After force-init: ragAvailable=${ragAvailable}`)
                // Re-check vector DB status
                const { isVectorDBAvailable } = await import("./vectorDB.js")
                log(`[RAG] 🔍 Vector DB available: ${isVectorDBAvailable()}`)
            } else {
                log(`[RAG] ❌ Force-initialization returned false`, "error")
                log(`[RAG] 🔍 This usually means ChromaDB initialization failed - check Vector DB logs above`)
            }
        } catch (initError) {
            log(`[RAG] ❌ Force-initialization error: ${initError.message}`, "error")
            log(`[RAG] ❌ Error stack: ${initError.stack}`, "error")
        }
    }
    
    if (documentFiles.length > 0 && ragAvailable) {
        log(`[RAG] 📄 Detected ${documentFiles.length} document(s) in chat message - auto-uploading to document storage...`)
        log(`[RAG] 🔍 Using user identifier for document storage: "${chatUserIdentifier}"`)
        for (const docFile of documentFiles) {
            try {
                // Convert base64 back to buffer
                const fileBuffer = Buffer.from(docFile.data, 'base64')
                const documentId = `doc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
                
                log(`[RAG] 🔄 Auto-uploading document: ${docFile.name} (${fileBuffer.length} bytes, type: ${docFile.type})`)
                
                // Process and store document
                const result = await processAndStoreDocument(
                    fileBuffer,
                    docFile.type || 'application/pdf',
                    docFile.name || 'document.pdf',
                    documentId,
                    chatUserIdentifier
                )
                
                log(`[RAG] ✅ Auto-uploaded document: ${docFile.name} - ${result.chunks} chunks stored`)
                log(`[RAG] 📄 Document preview (first 500 chars): ${result.text?.substring(0, 500) || 'N/A'}...`)
            } catch (docError) {
                log(`[RAG] ❌ Failed to auto-upload document ${docFile.name}: ${docError.message}`, "error")
                log(`[RAG] ❌ Error stack: ${docError.stack}`, "error")
                // Continue processing even if document upload fails
            }
        }
        // Wait a moment for ChromaDB to index
        await new Promise(resolve => setTimeout(resolve, 500))
        log(`[RAG] ⏳ Waited 500ms for document indexing...`)
    } else if (documentFiles.length > 0) {
        log(`[RAG] ⚠️  Documents detected but RAG not available - cannot auto-upload`)
        log(`[RAG] 🔧 Attempting to force-initialize RAG...`)
        
        // Try to force initialize RAG if it's not available
        if (openaiClient && !isRAGAvailable()) {
            try {
                log(`[RAG] 🔄 Force-initializing RAG with OpenAI client...`)
                const initResult = await initializeRAG(openaiClient)
                if (initResult) {
                    log(`[RAG] ✅ Force-initialization successful!`)
                    // Now try to upload documents
                    for (const docFile of documentFiles) {
                        try {
                            const fileBuffer = Buffer.from(docFile.data, 'base64')
                            const documentId = `doc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
                            
                            log(`[RAG] 🔄 Auto-uploading document after force-init: ${docFile.name} (${fileBuffer.length} bytes)`)
                            
                            const result = await processAndStoreDocument(
                                fileBuffer,
                                docFile.type || 'application/pdf',
                                docFile.name || 'document.pdf',
                                documentId,
                                chatUserIdentifier
                            )
                            
                            log(`[RAG] ✅ Auto-uploaded document: ${docFile.name} - ${result.chunks} chunks stored`)
                        } catch (docError) {
                            log(`[RAG] ❌ Failed to auto-upload document ${docFile.name}: ${docError.message}`, "error")
                        }
                    }
                } else {
                    log(`[RAG] ❌ Force-initialization failed - ChromaDB not available`, "error")
                    log(`[RAG] 🔧 FALLBACK: Extracting document content directly (bypassing RAG storage)...`)
                    
                    // CRITICAL FALLBACK: If RAG fails, extract document content directly and send to AI
                    try {
                        const { processDocument } = await import("./documentProcessor.js")
                        for (const docFile of documentFiles) {
                            try {
                                const fileBuffer = Buffer.from(docFile.data, 'base64')
                                log(`[RAG] 📄 Extracting text directly from ${docFile.name} (fallback mode)...`)
                                
                                const extractedText = await processDocument(
                                    fileBuffer,
                                    docFile.type || 'application/pdf',
                                    docFile.name || 'document.pdf'
                                )
                                
                                if (extractedText && extractedText.trim().length > 0) {
                                    // Store extracted text in a variable to be added to prompt later
                                    if (!req.directDocumentContent) {
                                        req.directDocumentContent = []
                                    }
                                    req.directDocumentContent.push({
                                        filename: docFile.name,
                                        content: extractedText,
                                        length: extractedText.length
                                    })
                                    log(`[RAG] ✅ Extracted ${extractedText.length} characters from ${docFile.name} (fallback mode)`)
                                    log(`[RAG] 📄 Preview: "${extractedText.substring(0, 500)}..."`)
                                } else {
                                    log(`[RAG] ⚠️  No text extracted from ${docFile.name}`)
                                }
                            } catch (extractError) {
                                log(`[RAG] ❌ Failed to extract text from ${docFile.name}: ${extractError.message}`, "error")
                            }
                        }
                    } catch (fallbackError) {
                        log(`[RAG] ❌ Fallback extraction failed: ${fallbackError.message}`, "error")
                    }
                }
            } catch (initError) {
                log(`[RAG] ❌ Force-initialization error: ${initError.message}`, "error")
                log(`[RAG] ❌ Error stack: ${initError.stack}`, "error")
                
                // CRITICAL FALLBACK: If initialization fails, extract document content directly
                log(`[RAG] 🔧 FALLBACK: Extracting document content directly (bypassing RAG storage)...`)
                try {
                    const { processDocument } = await import("./documentProcessor.js")
                    for (const docFile of documentFiles) {
                        try {
                            const fileBuffer = Buffer.from(docFile.data, 'base64')
                            log(`[RAG] 📄 Extracting text directly from ${docFile.name} (fallback mode)...`)
                            
                            const extractedText = await processDocument(
                                fileBuffer,
                                docFile.type || 'application/pdf',
                                docFile.name || 'document.pdf'
                            )
                            
                            if (extractedText && extractedText.trim().length > 0) {
                                if (!req.directDocumentContent) {
                                    req.directDocumentContent = []
                                }
                                req.directDocumentContent.push({
                                    filename: docFile.name,
                                    content: extractedText,
                                    length: extractedText.length
                                })
                                log(`[RAG] ✅ Extracted ${extractedText.length} characters from ${docFile.name} (fallback mode)`)
                                log(`[RAG] 📄 Preview: "${extractedText.substring(0, 500)}..."`)
                            }
                        } catch (extractError) {
                            log(`[RAG] ❌ Failed to extract text from ${docFile.name}: ${extractError.message}`, "error")
                        }
                    }
                } catch (fallbackError) {
                    log(`[RAG] ❌ Fallback extraction failed: ${fallbackError.message}`, "error")
                }
            }
        }
    }
    
    const temperature = 0.7
    
    // CRITICAL: Add document context to prompt even if RAG fails
    let documentContext = ""
    if (documentFiles.length > 0) {
        const docNames = documentFiles.map(f => f.name || 'document').join(', ')
        documentContext = `\n\n=== USER HAS UPLOADED DOCUMENTS ===
The user has uploaded ${documentFiles.length} document(s): ${docNames}

IMPORTANT: The user has attached these files to this message. Even if document processing encountered technical issues, you MUST acknowledge that the user has uploaded documents.

FORBIDDEN: NEVER say "I can't see documents" or "please upload again"
MANDATORY: Acknowledge the uploaded documents and help the user with their question about them.

The uploaded documents are: ${docNames}`
        log(`[RAG] 📄 Added document context to prompt (${documentFiles.length} file(s))`)
    }
    
    // Process uploaded files (images)
    let imageContext = ""
    if (files.length > 0) {
        log(`[File Upload] Received ${files.length} file(s)`)
        const imageFiles = files.filter((f) => f.type && f.type.startsWith('image/'))
        if (imageFiles.length > 0) {
            imageContext = `\n\n[User uploaded ${imageFiles.length} image(s): ${imageFiles.map((f) => f.name).join(', ')}]`
            log(`[File Upload] ${imageFiles.length} image(s) detected`)
        }
    }
    
    // mode: 'quick' (parallel) or 'refined' (sequential ChatGPT → Claude)
    log(`[API Request] Received mode parameter: "${mode}" (type: ${typeof mode})`)
    log(`[API Request] Mode check (mode === 'refined'): ${mode === 'refined'}`)

    if (!prompt || typeof prompt !== "string") {
        res.status(400).json({ error: "Prompt is required" })
        return
    }

    // Generate or use provided userId (needed for logging)
    // CRITICAL: Use consistent user identifier format - ALWAYS use authenticated user email first
    // Match the format used in document upload: req.user?.email || req.user?.id || "anonymous"
    // This ensures documents uploaded via chat are stored under the same ID as documents uploaded via /api/documents/upload
    const userIdentifier = req.user?.email || req.user?.id || userId || "anonymous"
    log(`[RAG] 🔍 User identifier for RAG: "${userIdentifier}" (from req.user: ${req.user?.email || req.user?.id || 'none'}, userId param: ${userId || 'not provided'})`)
    
    // Check if this is a calendar-related query (expanded keywords)
    const calendarKeywords = [
        'calendar', 'upcoming', 'due date', 'due dates', 'assignment', 'homework', 
        'deadline', 'schedule', 'event', 'events', 'what\'s coming', 'what is coming', 
        'whats coming', 'when is', 'when are', 'what do i have', 'what\'s on my calendar',
        'whats on my calendar', 'what\'s upcoming', 'whats upcoming', 'what is upcoming',
        'show me my', 'tell me about my', 'my assignments', 'my deadlines', 'my schedule',
        'tok', 'ee submission', 'extended essay', 'theory of knowledge'
    ]
    const promptLower = prompt.toLowerCase()
    const isCalendarQuery = calendarKeywords.some(keyword => promptLower.includes(keyword))
    
    log(`[Calendar] Query check: "${prompt.substring(0, 50)}..." | Is calendar query: ${isCalendarQuery}`)
    
    // Get user's calendar data if it's a calendar query
    let calendarContext = ""
    if (isCalendarQuery) {
        try {
            const userEmail = req.user?.email || userIdentifier
            const calendarData = getUserCalendar(userEmail)
            
            if (calendarData.dueDates && calendarData.dueDates.length > 0) {
                const today = new Date()
                const currentMonth = today.getMonth()
                const currentYear = today.getFullYear()
                
                // Format upcoming due dates
                const upcomingDueDates = calendarData.dueDates
                    .map(due => {
                        const [day, month] = due.dueDate.split('/')
                        const dueDate = new Date(currentYear, parseInt(month) - 1, parseInt(day))
                        const daysUntil = Math.ceil((dueDate - today) / (1000 * 60 * 60 * 24))
                        
                        return {
                            ...due,
                            daysUntil,
                            isPast: daysUntil < 0,
                            isToday: daysUntil === 0,
                            isUpcoming: daysUntil > 0
                        }
                    })
                    .sort((a, b) => a.daysUntil - b.daysUntil)
                
                const upcoming = upcomingDueDates.filter(d => d.isUpcoming || d.isToday)
                const past = upcomingDueDates.filter(d => d.isPast)
                
                calendarContext = `\n\n=== USER'S CALENDAR INFORMATION ===
The user is asking about their calendar. Here is their calendar data:

UPCOMING DUE DATES:
${upcoming.length > 0 ? upcoming.map(d => `- ${d.subject} - Due: ${d.dueDate} (${d.daysUntil === 0 ? 'TODAY' : d.daysUntil === 1 ? 'TOMORROW' : `in ${d.daysUntil} days`})`).join('\n') : 'No upcoming due dates'}

PAST DUE DATES:
${past.length > 0 ? past.map(d => `- ${d.subject} - Due: ${d.dueDate} (${Math.abs(d.daysUntil)} days ago)`).join('\n') : 'No past due dates'}

ALL DUE DATES (for reference):
${calendarData.dueDates && calendarData.dueDates.length > 0 ? calendarData.dueDates.map(d => `- ${d.subject} - Due: ${d.dueDate}`).join('\n') : 'No due dates'}

CLASSES:
${calendarData.classes && calendarData.classes.length > 0 ? calendarData.classes.map(c => `- ${c.block} ${c.level}: ${c.name} with ${c.teacher}`).join('\n') : 'No classes listed'}

CRITICAL INSTRUCTIONS:
1. When the user asks "what's upcoming in my calendar" or similar questions, list ALL upcoming due dates from the UPCOMING DUE DATES section above
2. Be specific about dates, subjects, and how many days until each deadline
3. If they ask about specific items (like "TOK" or "EE submission"), find them in the calendar data and tell them the exact due date
4. Always use the information from this calendar data - do NOT make up dates or events
5. Format your response clearly, listing each upcoming item with its due date`
                
                log(`[Calendar] Added calendar context to prompt (${upcoming.length} upcoming, ${past.length} past due dates, ${calendarData.dueDates?.length || 0} total)`)
            } else {
                calendarContext = `\n\n=== CALENDAR QUERY DETECTED ===
The user is asking about their calendar, but no calendar data is currently available. You can let them know they can add events to their calendar through the dashboard.`
                log(`[Calendar] Calendar query detected but no data available`)
            }
        } catch (calendarError) {
            log(`[Calendar] Error loading calendar context: ${calendarError.message}`, "error")
        }
    }
    
    // VERIFY: Check if user has documents AFTER auto-upload (if any happened)
    // Wait a moment for auto-upload to complete if documents were just uploaded
    if (documentFiles.length > 0) {
        log(`[RAG] ⏳ Waiting for auto-upload to complete before checking documents...`)
        await new Promise(resolve => setTimeout(resolve, 500)) // Small delay to ensure storage completes
    }
    
    if (isRAGAvailable()) {
        try {
            const { getUserDocuments } = await import("./vectorDB.js")
            const preCheckDocs = await getUserDocuments(userIdentifier)
            if (preCheckDocs && preCheckDocs.length > 0) {
                log(`[RAG] ✅ PRE-CHECK: User "${userIdentifier}" has ${preCheckDocs.length} document(s) available`)
                log(`[RAG] 📋 Document IDs: ${preCheckDocs.map(d => d.documentId || 'unknown').join(', ')}`)
            } else {
                log(`[RAG] ⚠️  PRE-CHECK: User "${userIdentifier}" has NO documents in vector DB`)
                if (documentFiles.length > 0) {
                    log(`[RAG] ⚠️  WARNING: Documents were detected but not found in DB - auto-upload may have failed`)
                }
            }
        } catch (preCheckError) {
            log(`[RAG] ⚠️  PRE-CHECK failed: ${preCheckError.message}`, "error")
        }
    }
    
    // Check if this is an image generation request
    const isImageGenRequest = isImageGenerationRequest(prompt)
    console.log(`[Image Detection] Prompt: "${prompt}" | Is Image Request: ${isImageGenRequest}`)
    
    if (isImageGenRequest) {
        try {
            const imageStartTime = Date.now()
            console.log("[Image Generation] Starting image generation...")
            
            // Extract image description from prompt
            let imagePrompt = prompt.trim()
            
            // Remove common image generation phrases to get the actual description
            imagePrompt = imagePrompt.replace(/^(generate|create|make|draw|show me|visualize|illustrate)\s+(an?\s+)?(image|picture|photo|drawing|illustration)\s+(of\s+)?/i, "")
            imagePrompt = imagePrompt.replace(/\b(image|picture|photo|drawing|illustration)\s+(of|showing|depicting)\s+/gi, "")
            imagePrompt = imagePrompt.replace(/\b(can you|please|i want|give me)\s+(generate|create|make|draw|show)\s+(an?\s+)?(image|picture|photo|drawing)\s+(of\s+)?/gi, "")
            imagePrompt = imagePrompt.replace(/^i\s+want\s+(an?\s+)?(image|picture|photo|drawing)\s+(of\s+)?/i, "")
            imagePrompt = imagePrompt.replace(/^give\s+me\s+(an?\s+)?(image|picture|photo|drawing)\s+(of\s+)?/i, "")
            
            // Clean up extra spaces
            imagePrompt = imagePrompt.replace(/\s+/g, " ").trim()
            
            if (!imagePrompt) {
                imagePrompt = prompt // Fallback to original prompt
            }

            console.log(`[Image Generation] Cleaned prompt: "${imagePrompt}"`)

            // Generate image using DALL-E
            const imageResponse = await openaiClient.images.generate({
                model: "dall-e-3",
                prompt: imagePrompt.trim(),
                n: 1,
                size: "1024x1024",
                quality: "standard",
                response_format: "url"
            })

            const imageUrl = imageResponse.data[0]?.url
            const imageGenerationTime = Date.now() - imageStartTime

            if (!imageUrl) {
                throw new Error("Failed to generate image - no URL returned")
            }

            console.log(`[Image Generation] Success! Image URL: ${imageUrl} (${imageGenerationTime}ms)`)

            // Save image generation log
            const conversationLog = {
                id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                timestamp: new Date().toISOString(),
                userId: userIdentifier,
                prompt: prompt.substring(0, 500),
                promptLength: prompt.length,
                response: `Image generated: ${imagePrompt.trim()}`,
                responseLength: 0,
                model: "dall-e-3",
                conversationHistoryLength: conversationHistory?.length || 0,
                timing: {
                    total: imageGenerationTime,
                    chatgpt: 0,
                    claude: 0,
                    fusion: 0,
                },
                tokens: {
                    total: 0,
                    chatgpt: 0,
                    claude: 0,
                    fusion: 0,
                },
                toneAdapted: Boolean(userProfiles.get(userIdentifier)?.tone),
                isImageGeneration: true,
                isPageScan: false,
                chatgptSuccess: false,
                claudeSuccess: false,
                imageUrl: imageUrl,
                imagePrompt: imagePrompt.trim(),
                systemPrompt: system || null,
            }
            saveConversationLog(conversationLog)
            updateAnalytics({
                messageCount: conversationHistory?.length || 0,
                tokensUsed: 0,
                responseTime: imageGenerationTime,
                model: "dall-e-3",
                failed: false,
                isImageGeneration: true,
                isPageScan: false,
                toneAdapted: Boolean(userProfiles.get(userIdentifier)?.tone),
                userId: userIdentifier,
            })

            // Return image URL with a text response
            res.json({
                reply: `I've generated an image for you: "${imagePrompt.trim()}"\n\n![Generated Image](${imageUrl})`,
                imageUrl: imageUrl,
                imagePrompt: imagePrompt.trim(),
                model: "dall-e-3",
                type: "image"
            })
            return
        } catch (error) {
            console.error("[Image Generation] Error:", error)
            // If image generation fails, return error instead of falling through
            res.status(500).json({
                error: "Image generation failed. Please try again or rephrase your request.",
                details: error.message,
                fallback: "You can try asking for text-based information instead."
            })
            return
        }
    }

    // Track timing
    const requestStartTime = Date.now()
    let chatgptStartTime = 0
    let chatgptEndTime = 0
    let claudeStartTime = 0
    let claudeEndTime = 0
    let fusionStartTime = 0
    let fusionEndTime = 0
    
    // Detect if this is a page scan or image generation
    const isPageScan = prompt.includes("--- PAGE CONTENT ---")
    const isImageReq = isImageGenerationRequest(prompt)
    
    // Log user prompt
    console.log("")
    console.log("=".repeat(80))
    console.log(`[${new Date().toISOString()}] USER PROMPT`)
    console.log(`User ID: ${userIdentifier}`)
    console.log(`Prompt: "${prompt.substring(0, 200)}${prompt.length > 200 ? "..." : ""}"`)
    if (system) {
        console.log(`System Instructions: "${system}"`)
    }
    if (conversationHistory && conversationHistory.length > 0) {
        console.log(`Conversation History: ${conversationHistory.length} messages`)
    }
    if (isPageScan) {
        console.log(`📄 Page Scan Request Detected`)
    }
    if (isImageReq) {
        console.log(`🖼️  Image Generation Request Detected`)
    }
    console.log("-".repeat(80))
    console.log(`[AI Integration Check]`)
    console.log(`  ✅ ChatGPT Client: ${openaiClient ? "Ready" : "❌ Not configured"}`)
    console.log(`  ${anthropicClient ? "✅" : "❌"} Claude Client: ${anthropicClient ? "Ready" : "❌ Not configured"}`)
    console.log(`  ChatGPT Model: ${process.env.OPENAI_MODEL || "gpt-4o-mini"}`)
    console.log(`  Claude Model: ${process.env.ANTHROPIC_MODEL || "claude-3-5-sonnet-20240620 (default)"}`)
    if (process.env.ANTHROPIC_MODEL && process.env.ANTHROPIC_MODEL.includes("20241022")) {
        console.log(`  ⚠️  WARNING: Your Claude model name "${process.env.ANTHROPIC_MODEL}" is invalid!`)
        console.log(`  ⚠️  Update your .env file: ANTHROPIC_MODEL=claude-3-5-sonnet-20240620`)
    }
    console.log("-".repeat(80))
    
    // RAG: Retrieve documents FIRST before building system prompt
    let ragContext = ""
    let retrievedDocs = []
    let citations = []
    let hasDocuments = false
    let userDocs = [] // Store user documents for later use
    
    if (isRAGAvailable()) {
        try {
            // Check if user has documents
            const { getUserDocuments } = await import("./vectorDB.js")
            log(`[RAG] 🔍 Checking for documents for user: "${userIdentifier}"`)
            userDocs = await getUserDocuments(userIdentifier)
            hasDocuments = userDocs && userDocs.length > 0
            log(`[RAG] 📊 getUserDocuments returned: ${userDocs.length} document(s) for user "${userIdentifier}"`)
            
            if (hasDocuments) {
                log(`[RAG] 📚 User has ${userDocs.length} uploaded document(s) - retrieving relevant content...`)
                log(`[RAG] 🔍 User prompt: "${prompt.substring(0, 100)}..."`)
                log(`[RAG] 🔍 User identifier: "${userIdentifier}"`)
                log(`[RAG] 🔍 Document IDs: ${userDocs.map(d => d.documentId || 'unknown').join(', ')}`)
                
                // Get the original prompt for RAG search (before image context)
                const searchQuery = prompt || finalPrompt
                log(`[RAG] 🔎 Strategy 1: Searching with full query (${searchQuery.length} chars)...`)
                log(`[RAG] 🔎 Query text: "${searchQuery}"`)
                // Retrieve ALL chunks from user's documents (not just 50)
                retrievedDocs = await retrieveRelevantDocuments(searchQuery, userIdentifier, 200)
                log(`[RAG] 📊 Strategy 1 result: ${retrievedDocs.length} chunks found`)
                if (retrievedDocs.length > 0) {
                    log(`[RAG] 📄 First chunk preview: "${retrievedDocs[0].text.substring(0, 200)}..."`)
                }
                
                // Multiple fallback strategies
                if (retrievedDocs.length === 0) {
                    const keywords = searchQuery.split(/\s+/).filter(w => w.length > 3).slice(0, 5).join(" ")
                    log(`[RAG] 🔎 Strategy 2: Searching with keywords: "${keywords}"...`)
                    retrievedDocs = await retrieveRelevantDocuments(keywords, userIdentifier, 200)
                    log(`[RAG] 📊 Strategy 2 result: ${retrievedDocs.length} chunks found`)
                }
                
                if (retrievedDocs.length === 0) {
                    // Get ANY documents as fallback
                    log(`[RAG] 🔎 Strategy 3: Fallback - retrieving ANY documents...`)
                    retrievedDocs = await retrieveRelevantDocuments("document", userIdentifier, 200)
                    log(`[RAG] 📊 Strategy 3 result: ${retrievedDocs.length} chunks found`)
                }
                
                if (retrievedDocs.length > 0) {
                    ragContext = formatRetrievedContext(retrievedDocs)
                    citations = retrievedDocs.map((doc, index) => ({
                        source: doc.metadata.filename || "Document",
                        relevance: Math.round(doc.relevance * 100),
                        index: index + 1,
                    }))
                    log(`[RAG] ✅ Retrieved ${retrievedDocs.length} document chunks (context length: ${ragContext.length} chars)`)
                    log(`[RAG] 📄 Sample context preview: "${ragContext.substring(0, 500)}..."`)
                    log(`[RAG] 📄 Full context length: ${ragContext.length} characters`)
                } else {
                    // CRITICAL: Even if retrieval fails, we know documents exist
                    // Create a fallback context that tells the AI documents were uploaded
                    log(`[RAG] ⚠️  Retrieval returned 0 chunks, but user HAS ${userDocs.length} document(s)`)
                    log(`[RAG] 🔧 Creating fallback context to inform AI about documents...`)
                    const documentNames = userDocs.map(d => d.filename || d.documentId || 'Document').join(', ')
                    ragContext = `\n\n=== USER HAS UPLOADED DOCUMENTS ===
The user has uploaded ${userDocs.length} document(s): ${documentNames}

IMPORTANT: Even though document content retrieval encountered a technical issue, the user HAS uploaded documents. You MUST acknowledge this and work with the user. NEVER ask them to reupload - the documents are already in the system.

If the user asks about their uploaded documents, acknowledge that they have uploaded: ${documentNames}
Ask them what specific information they need from these documents, or what they'd like to know about them.

CRITICAL: NEVER say "I can't read files" or ask them to reupload. The documents exist - acknowledge them and help the user.`
                    log(`[RAG] ✅ Created fallback context (${ragContext.length} chars)`)
                    log(`[RAG] ⚠️  WARNING: User has ${userDocs.length} document(s) but retrieval returned 0 chunks!`)
                    log(`[RAG] 🔍 Debugging: userIdentifier="${userIdentifier}", documentIds=${userDocs.map(d => d.documentId).join(', ')}`)
                    log(`[RAG] 🔧 Attempting to get documents directly from vectorDB...`)
                    // Last resort: try to get documents directly
                    try {
                        const { searchSimilarChunks, getCollection } = await import("./vectorDB.js")
                        const collection = getCollection()
                        if (collection) {
                            // Try to get ALL documents for this user (no query filter) - get ALL chunks
                            const allDocs = await collection.get({
                                where: { userId: userIdentifier },
                                limit: 1000 // Get ALL chunks, not just 50
                            })
                            log(`[RAG] 🔍 Direct collection query: found ${allDocs.ids?.length || 0} chunks for user`)
                            if (allDocs.ids && allDocs.ids.length > 0) {
                                // Convert to expected format - get ALL chunks
                                retrievedDocs = allDocs.documents[0].map((text, index) => ({
                                    text,
                                    metadata: allDocs.metadatas[0][index] || {},
                                    relevance: 1.0, // High relevance since these are the user's documents
                                    distance: 0
                                }))
                                ragContext = formatRetrievedContext(retrievedDocs)
                                log(`[RAG] ✅ Direct collection retrieval successful: ${retrievedDocs.length} chunks`)
                                log(`[RAG] 📄 Direct retrieval context length: ${ragContext.length} characters`)
                                log(`[RAG] 📄 First chunk from direct retrieval: "${retrievedDocs[0]?.text?.substring(0, 300)}..."`)
                            } else {
                                // Try without user filter (fallback)
                                const allDocsNoFilter = await collection.get({ limit: 100 })
                                log(`[RAG] 🔍 Collection query without filter: found ${allDocsNoFilter.ids?.length || 0} total chunks`)
                                if (allDocsNoFilter.ids && allDocsNoFilter.ids.length > 0) {
                                    retrievedDocs = allDocsNoFilter.documents[0].map((text, index) => ({
                                        text,
                                        metadata: allDocsNoFilter.metadatas[0][index] || {},
                                        relevance: 0.8,
                                        distance: 0
                                    }))
                                    ragContext = formatRetrievedContext(retrievedDocs)
                                    log(`[RAG] ✅ Fallback retrieval successful: ${retrievedDocs.length} chunks`)
                                }
                            }
                        }
                    } catch (directError) {
                        log(`[RAG] ❌ Direct retrieval also failed: ${directError.message}`, "error")
                        log(`[RAG] ❌ Error stack: ${directError.stack}`, "error")
                    }
                }
            }
        } catch (error) {
            log(`[RAG] ⚠️  Error retrieving documents: ${error.message}`, "error")
        }
    }
    
    // Get adaptive system prompt based on conversation history
    let adaptiveSystemPrompt = await getAdaptiveSystemPrompt(userIdentifier, conversationHistory, system)
    const toneAdapted = Boolean(userProfiles.get(userIdentifier)?.tone)
    
    // Check if images were uploaded
    const imageFiles = files.filter((f) => f.type && f.type.startsWith('image/'))
    const hasImages = imageFiles && imageFiles.length > 0
    
    // Add STRONG RAG instruction to system prompt if documents exist
    // CRITICAL: Always add this if user has documents, even if retrieval failed
    if (hasDocuments) {
        const docCount = userDocs?.length || 0
        const docNames = userDocs?.map(d => d.filename || d.documentId || 'Document').join(', ') || 'documents'
        log(`[RAG] 🔒 Adding document handling instructions (hasDocuments=${hasDocuments}, docCount=${docCount}, retrievedDocs=${retrievedDocs.length})`)
        const ragInstruction = `\n\n=== ⚠️ CRITICAL: DOCUMENT HANDLING - USE DOCUMENT CONTENT ONLY ===
YOU ARE Lumra AI. The user has uploaded documents that you CAN and MUST access.

ABSOLUTE REQUIREMENTS:
1. USE ONLY information from the uploaded documents - DO NOT use general knowledge or training data
2. If information is NOT in the documents, explicitly say "This information is not in the uploaded document(s)"
3. DO NOT make up, guess, or infer information not explicitly in the documents
4. DO NOT provide generic information - the user wants SPECIFIC information from THEIR documents
5. When document content is provided, you MUST use it to answer immediately
6. Always cite sources when referencing document content (e.g., "According to [filename]..." or "As mentioned in the document...")
7. The document content will appear below marked as "DOCUMENT CONTENT FROM USER'S UPLOADED FILES"

FORBIDDEN PHRASES - NEVER USE THESE:
- "I can't open files" or "I can't read documents"
- "I'm afraid I still cannot" or "I cannot directly analyze"
- "please share the text" or "copy and paste the content"
- "I need you to provide" or "I don't have access to files"
- ANY variation of saying you can't read files
- Using general knowledge instead of document content
- Making up information not in the documents

CRITICAL: You ARE able to read and analyze documents - the content WILL be provided to you. Use ONLY that content, not general knowledge.`
        adaptiveSystemPrompt = adaptiveSystemPrompt ? adaptiveSystemPrompt + ragInstruction : ragInstruction.trim()
        log(`[RAG] 🔒 Added STRONG document handling instructions to system prompt (user has ${hasDocuments ? 'documents' : 'no documents'})`)
    }
    
    // Add STRONG IMAGE ANALYSIS instruction if images were uploaded
    if (hasImages) {
        const imageInstruction = `\n\n=== CRITICAL: IMAGE ANALYSIS ===
YOU ARE Lumra AI. The user has uploaded ${imageFiles.length} image(s) that you CAN and MUST analyze.

IMPORTANT RULES:
1. NEVER say "I can't see images", "I can't analyze images", "I can't view images", or "I don't have access to images"
2. NEVER say "please describe the image" or "I need you to tell me what's in the image"
3. The images are included in this message - you CAN see and analyze them directly
4. When the user asks to "analyze", "describe", "explain", "review", or asks "what's in this image" - they mean the uploaded image(s)
5. You MUST analyze the image(s) and provide detailed descriptions, insights, or answers based on what you see
6. Describe what you see in the image(s) clearly and accurately
7. If asked about specific elements in the image, identify and discuss them

REMEMBER: You ARE able to see and analyze images - they are provided to you in this conversation. Use your vision capabilities to analyze them.`
        adaptiveSystemPrompt = adaptiveSystemPrompt ? adaptiveSystemPrompt + imageInstruction : imageInstruction.trim()
        log(`[Image Analysis] ✅ Added image analysis instructions to system prompt (${imageFiles.length} image(s))`)
    }
    
    // Add calendar context if it's a calendar-related query
    if (calendarContext) {
        adaptiveSystemPrompt = adaptiveSystemPrompt ? adaptiveSystemPrompt + calendarContext : calendarContext.trim()
        log(`[Calendar] ✅ Added calendar context to system prompt`)
    }

    try {
        const isRefinedMode = mode === 'refined'
        
        // For Quick Mode: Use reduced history (3-5 messages) for faster processing
        // For Refined Mode: Keep full history (10 messages) for better context
        const historyLimit = isRefinedMode ? 10 : 5
        const recentHistory = conversationHistory
            ? conversationHistory.slice(-historyLimit).filter((msg) => msg.role !== "system")
            : []
        
        // Add image and document context to the prompt if files were uploaded
        let finalPrompt = prompt
        if (documentContext) {
            finalPrompt = finalPrompt + documentContext
        }
        if (imageContext) {
            finalPrompt = finalPrompt + imageContext
        }
        
        // RAG context was already retrieved above - it will be added to user message separately
        // (We don't add it to finalPrompt here because we want to format it more prominently)
        if (ragContext && retrievedDocs.length > 0) {
            log(`[RAG] ✅ Retrieved ${retrievedDocs.length} document chunks - will be added to user message`)
            log(`[RAG] 📄 RAG context length: ${ragContext.length} characters`)
        } else if (hasDocuments && retrievedDocs.length === 0) {
            // User has documents but retrieval failed - add a note
            log(`[RAG] ⚠️  User has documents but retrieval returned empty - this may indicate an issue`)
        } else if (!hasDocuments) {
            log(`[RAG] ℹ️  No documents uploaded by user yet`)
        }
        
        // Make citations available in all scopes (for refined mode and quick mode)
        const ragCitations = citations
        
        // For Quick Mode: Always use Claude Haiku (faster and cheaper)
        // For Refined Mode: Already uses Haiku (defined in refined mode section)
        let claudeModel = process.env.ANTHROPIC_MODEL || "claude-3-haiku-20240307"
        
        // Quick Mode optimization: Force Haiku for speed
        if (!isRefinedMode) {
            claudeModel = "claude-3-haiku-20240307" // Always use Haiku for Quick Mode
            log(`[Quick Mode] ⚡ Using Claude Haiku for faster responses`)
        }
        
        // Fix invalid Claude model names
        if (claudeModel.includes("20241022") || claudeModel.includes("202410")) {
            log(`[AI Integration] ⚠️  Invalid Claude model detected: "${claudeModel}" - Using Haiku instead`, 'error')
            claudeModel = "claude-3-haiku-20240307"
        }
        
        log(`[AI Integration] Mode: ${isRefinedMode ? 'REFINED (ChatGPT → Claude)' : 'QUICK (Parallel + Optimized)'}`)
        log(`[AI Integration] ChatGPT Model: ${process.env.OPENAI_MODEL || "gpt-4o-mini"}`)
        log(`[AI Integration] Claude Model: ${claudeModel}`)
        log(`[AI Integration] History Limit: ${historyLimit} messages`)
        
        // REFINED MODE: Sequential pipeline (ChatGPT → Claude)
        if (isRefinedMode) {
            log(`[Refined Mode] ===== STARTING REFINED MODE =====`)
            log(`[Refined Mode] Mode parameter received: "${mode}"`)
            log(`[Refined Mode] isRefinedMode check: ${isRefinedMode}`)
            log(`[Refined Mode] Step 1: ChatGPT generating initial response...`)
            chatgptStartTime = Date.now()
            
            let chatgptReply = ""
            let chatgptTokens = 0
            let chatgptTime = 0
            
            try {
                // Prepare user message with images if any (for refined mode)
                const imageFilesRefined = files.filter((f) => f.type && f.type.startsWith('image/'))
                let userMessageRefined
                
                // CRITICAL: Add RAG context FIRST if documents exist
                let refinedPromptText = finalPrompt
                if (ragContext && retrievedDocs.length > 0) {
                    // Make RAG context very explicit at the start with STRONG instructions
                    refinedPromptText = `=== ⚠️ CRITICAL: USE DOCUMENT CONTENT ONLY - NO GENERAL KNOWLEDGE ===

YOU ARE Lumra AI. The user has uploaded documents. Below is the ACTUAL CONTENT from those documents.

ABSOLUTE REQUIREMENTS:
1. READ the document content below carefully
2. USE ONLY the information from the documents below to answer the question
3. DO NOT use your training data or general knowledge - ONLY use what's in the documents
4. If information is NOT in the documents, explicitly say "This information is not in the uploaded document(s)"
5. DO NOT make up, guess, or infer information not explicitly in the documents
6. DO NOT provide generic information - the user wants SPECIFIC information from THEIR documents

FORBIDDEN:
- NEVER say "I can't open files" or "I can't read documents" - you HAVE the file content below
- NEVER use general knowledge about topics - ONLY use document content
- NEVER guess or infer information not explicitly in the documents
- NEVER provide generic information - the user wants specific information from THEIR documents

=== USER'S QUESTION ===
${prompt}

=== DOCUMENT CONTENT FROM USER'S UPLOADED FILES (READ THIS CAREFULLY) ===
${ragContext}

=== END OF DOCUMENT CONTENT ===

REMEMBER: Answer the user's question using ONLY the information from the documents above. If the information is not in the documents, explicitly state "This information is not in the uploaded document(s)". DO NOT use general knowledge.`
                    log(`[Refined Mode] 📝 Enhanced prompt with STRONG RAG context (${refinedPromptText.length} chars, ${retrievedDocs.length} chunks)`)
                } else if (hasDocuments) {
                    refinedPromptText = `=== CRITICAL INSTRUCTION: DOCUMENT ACCESS ===
YOU ARE Lumra AI. The user has uploaded documents.

FORBIDDEN: NEVER say "I can't read files" or "I can't access documents"

MANDATORY: Acknowledge that documents were uploaded and work with the user. Ask clarifying questions about what they need from their documents.

=== USER'S QUESTION ===
${prompt}

Note: Document content retrieval encountered an issue, but documents were uploaded. Help the user with their question.`
                    log(`[Refined Mode] ⚠️  User has documents but RAG context is empty - added fallback message`)
                }
                
                // Add image analysis instruction to prompt if images are present
                if (imageFilesRefined.length > 0) {
                    const imageNote = `\n\n=== IMAGE ANALYSIS REQUEST ===\nThe user has uploaded ${imageFilesRefined.length} image(s) for you to analyze. Please examine the image(s) included in this message and provide a detailed analysis based on what you see.`
                    refinedPromptText = refinedPromptText + imageNote
                    log(`[Refined Mode] 📝 Added image analysis note to prompt (${imageFilesRefined.length} image(s))`)
                }
                
                if (imageFilesRefined.length > 0) {
                    userMessageRefined = {
                        role: "user",
                        content: [
                            { type: "text", text: refinedPromptText },
                            ...imageFilesRefined.map((file) => ({
                                type: "image_url",
                                image_url: { url: `data:${file.type};base64,${file.data}` }
                            }))
                        ]
                    }
                } else {
                    userMessageRefined = { role: "user", content: refinedPromptText }
                }
                
                // Step 1: ChatGPT generates initial response
                const chatgptResult = await openaiClient.chat.completions.create({
                    model: process.env.OPENAI_MODEL || "gpt-4o-mini",
                    temperature,
                    messages: [
                        ...(adaptiveSystemPrompt ? [{ role: "system", content: adaptiveSystemPrompt }] : []),
                        ...recentHistory,
                        userMessageRefined,
                    ],
                })
            
                chatgptEndTime = Date.now()
                chatgptTime = chatgptEndTime - chatgptStartTime
                
                chatgptReply = chatgptResult.choices[0]?.message?.content?.trim() || ""
                chatgptTokens = chatgptResult.usage?.total_tokens || 0
            
                log(`[Refined Mode] Step 1 Complete: ChatGPT generated ${chatgptReply.length} chars (${chatgptTokens} tokens, ${chatgptTime}ms)`)
                
                if (!chatgptReply) {
                    throw new Error("ChatGPT failed to generate initial response")
                }
                
                // Step 2: Claude refines ChatGPT's response
                log(`[Refined Mode] Step 2: Claude refining ChatGPT's response...`)
                claudeStartTime = Date.now()
                
                // Prepare refinement prompt with image instructions if needed
                const imageFilesForClaude = files.filter((f) => f.type && f.type.startsWith('image/'))
                
                // CRITICAL: Include RAG context in refinement prompt so Claude can use documents if ChatGPT missed them
                let ragContextForRefinement = ""
                if (ragContext && retrievedDocs.length > 0) {
                    ragContextForRefinement = `\n\n=== CRITICAL: USER HAS UPLOADED DOCUMENTS ===
The user has uploaded documents that contain relevant information. The document content is provided below. If the initial response didn't properly use this document content, you MUST incorporate it into your refined response.

${ragContext}

REMEMBER: You CAN and MUST use the document content above. NEVER say "I can't read files" or "I can't access documents". The content is provided to you right here.`
                    log(`[Refined Mode] 📚 Added RAG context to Claude refinement prompt (${retrievedDocs.length} chunks)`)
                }
                
                const refinementPrompt = `You are Lumra AI, an expert at refining and improving content. Below is an initial response that needs refinement.${imageFilesForClaude.length > 0 ? `\n\nIMPORTANT: The user has uploaded ${imageFilesForClaude.length} image(s). The initial response should have analyzed these images. If the initial response didn't properly analyze the images, you MUST analyze them now and provide a comprehensive image analysis.` : ''}${ragContextForRefinement}

**Initial Response:**
${chatgptReply}

**Your task:** Refine and improve this response by:
1. Improving clarity and articulation
2. Better organization and structure
3. Enhanced readability and flow
4. Polishing language while preserving the original intent
5. Adding proper formatting if needed (headings, bullet points, paragraphs)

CRITICAL: 
- You are Lumra AI - always identify yourself as Lumra AI
- NEVER mention "ChatGPT", "refined version", or "Here is a refined version"
- Simply provide the improved response directly as Lumra AI
- Do NOT add any introductory text like "Here is a refined version" - just give the refined response

Preserve all the key information and meaning, but make it more professional, clear, and well-organized. Provide the refined response directly:`
                
                log(`[Refined Mode] Calling Claude API...`)
                log(`[Refined Mode] Initial Claude model from env: ${process.env.ANTHROPIC_MODEL || "not set"}`)
                log(`[Refined Mode] Claude model after first fix: ${claudeModel}`)
                log(`[Refined Mode] Anthropic client available: ${anthropicClient ? 'YES' : 'NO'}`)
                
                if (!anthropicClient) {
                    throw new Error("Anthropic client is not configured. Cannot use Refined Mode.")
                }
                
                // CRITICAL FIX: For refined mode, use Claude 3 Haiku (widely available and fast)
                // Since user has access to claude-3-haiku-20240307, we'll use that
                // Haiku is perfect for refinement tasks - it's fast and cost-effective
                const finalClaudeModel = "claude-3-haiku-20240307" // Using Haiku - user has access to this
                
                log(`[Refined Mode] ✅ Using Claude 3 Haiku: "${finalClaudeModel}"`)
                log(`[Refined Mode] ℹ️  Haiku is fast and efficient for refining ChatGPT responses`)
                log(`[Refined Mode] Anthropic client available: ${anthropicClient ? 'YES' : 'NO'}`)
                
                // Verify Anthropic API key is configured and valid
                if (!anthropicKey) {
                    log(`[Refined Mode] ❌ ANTHROPIC_API_KEY is not set in .env file!`, 'error')
                    throw new Error("Anthropic API key is not configured. Cannot use Refined Mode. Please set ANTHROPIC_API_KEY in your .env file.")
                }
                
                // Check API key format
                const apiKeyStr = String(anthropicKey)
                log(`[Refined Mode] Anthropic API key configured: YES (length: ${apiKeyStr.length})`)
                log(`[Refined Mode] API key starts with: ${apiKeyStr.substring(0, 7)}...`)
                
                // Anthropic API keys should start with "sk-ant-"
                if (!apiKeyStr.startsWith("sk-ant-") && !apiKeyStr.startsWith("sk-")) {
                    log(`[Refined Mode] ⚠️  WARNING: API key format looks incorrect. Should start with "sk-ant-"`, 'error')
                }
                
                // Check if API key looks like a placeholder
                if (apiKeyStr.includes("your-") || apiKeyStr.includes("placeholder") || apiKeyStr.length < 20) {
                    log(`[Refined Mode] ❌ ERROR: API key appears to be a placeholder! Please set a real ANTHROPIC_API_KEY in .env file.`, 'error')
                    throw new Error("Anthropic API key appears to be a placeholder. Please set a valid ANTHROPIC_API_KEY in your .env file.")
                }
                
                if (!anthropicClient) {
                    throw new Error("Anthropic client is not initialized. Cannot use Refined Mode.")
                }
                
                log(`[Refined Mode] Making API call with model: "${finalClaudeModel}"`)
                
                // Prepare Claude message - include images if they were in the original request
                // CRITICAL: Declare claudeRefinementMessage before using it
                let claudeRefinementMessage
                if (imageFilesForClaude && imageFilesForClaude.length > 0) {
                    // Extract pure base64 data for Claude (Claude requires base64 without data: prefix)
                    const claudeImages = imageFilesForClaude.map((file) => {
                        // Extract base64 data (remove data:image/type;base64, prefix if present)
                        let base64Data = file.data
                        if (base64Data.includes(',')) {
                            base64Data = base64Data.split(',')[1]
                        }
                        return {
                            type: "image",
                            source: {
                                type: "base64",
                                media_type: file.type || "image/png",
                                data: base64Data
                            }
                        }
                    })
                    
                    // Include images so Claude can see them when refining (important for image-based queries)
                    claudeRefinementMessage = {
                        role: "user",
                        content: [
                            { type: "text", text: refinementPrompt },
                            ...claudeImages
                        ]
                    }
                    log(`[Refined Mode] Including ${imageFilesForClaude.length} image(s) in refinement request`)
                } else {
                    claudeRefinementMessage = { role: "user", content: refinementPrompt }
                }
                
                // Make the API call with the guaranteed valid model
                log(`[Refined Mode] Attempting Anthropic API call...`)
                let claudeRefinementResult
                try {
                    claudeRefinementResult = await anthropicClient.messages.create({
                        model: finalClaudeModel, // Using Claude 3 Haiku: claude-3-haiku-20240307
                        temperature: temperature * 0.8,
                        max_tokens: Number(process.env.ANTHROPIC_MAX_TOKENS) || 2048,
                        system: adaptiveSystemPrompt 
                            ? `${adaptiveSystemPrompt}\n\nYou are an expert content editor who refines AI-generated responses to be clearer, better organized, and more articulate.`
                            : "You are an expert content editor who refines AI-generated responses to be clearer, better organized, and more articulate.",
                        messages: [
                            claudeRefinementMessage,
                        ],
                    })
                    log(`[Refined Mode] ✅ API call succeeded!`)
                } catch (claudeApiError) {
                    // Log detailed API error before re-throwing
                    log(`[Refined Mode] ❌ Claude API call failed!`, 'error')
                    log(`[Refined Mode] Error type: ${claudeApiError.constructor?.name || 'Unknown'}`, 'error')
                    log(`[Refined Mode] Error message: ${claudeApiError.message || 'No message'}`, 'error')
                    if (claudeApiError.status) log(`[Refined Mode] HTTP Status: ${claudeApiError.status}`, 'error')
                    if (claudeApiError.error) {
                        log(`[Refined Mode] Error object: ${JSON.stringify(claudeApiError.error, null, 2)}`, 'error')
                    }
                    if (claudeApiError.response) {
                        log(`[Refined Mode] Response status: ${claudeApiError.response.status}`, 'error')
                        if (claudeApiError.response.data) {
                            log(`[Refined Mode] Response data: ${JSON.stringify(claudeApiError.response.data, null, 2)}`, 'error')
                        }
                    }
                    // Re-throw to be caught by outer catch block
                    throw claudeApiError
                }
                claudeEndTime = Date.now()
                let claudeTime = claudeEndTime - claudeStartTime
                
                let refinedReply = claudeRefinementResult.content
                    ?.map((block) => ("text" in block ? block.text : ""))
                    .join("\n")
                    .trim() || chatgptReply // Fallback to ChatGPT's response if Claude fails
                
                let claudeTokens = (claudeRefinementResult.usage?.input_tokens || 0) + (claudeRefinementResult.usage?.output_tokens || 0)
                let totalTokens = chatgptTokens + claudeTokens
                let totalResponseTime = Date.now() - requestStartTime
                
                // Calculate costs
                const chatgptModel = getModelName(process.env.OPENAI_MODEL || "gpt-4o-mini")
                const chatgptInputTokens = chatgptResult.usage?.prompt_tokens || 0
                const chatgptOutputTokens = chatgptResult.usage?.completion_tokens || 0
                const openaiCost = calculateTokenCost(chatgptModel, chatgptInputTokens, chatgptOutputTokens)
                
                const claudeInputTokens = claudeRefinementResult.usage?.input_tokens || 0
                const claudeOutputTokens = claudeRefinementResult.usage?.output_tokens || 0
                const anthropicCost = calculateTokenCost(finalClaudeModel, claudeInputTokens, claudeOutputTokens)
                const totalCost = openaiCost + anthropicCost
                
                log(`[Refined Mode] Step 2 Complete: Claude refined to ${refinedReply.length} chars (${claudeTokens} tokens, ${claudeTime}ms)`)
                log(`[Refined Mode] Total: ${refinedReply.length} chars, ${totalTokens} tokens, ${totalResponseTime}ms`)
                log(`[Refined Mode] Cost: OpenAI: $${openaiCost.toFixed(6)}, Anthropic: $${anthropicCost.toFixed(6)}, Total: $${totalCost.toFixed(6)}`)
                log(`[Refined Mode] Timing: ChatGPT: ${chatgptTime}ms | Claude: ${claudeTime}ms | Total: ${totalResponseTime}ms`)
                log(`[Refined Mode] Response preview: ${refinedReply.substring(0, 300)}${refinedReply.length > 300 ? "..." : ""}`)
                log(`[Refined Mode] ${"=".repeat(60)}`)
                
                // Save conversation log for refined mode
                const conversationLog = {
                id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                timestamp: new Date().toISOString(),
                userId: userIdentifier,
                prompt: prompt.substring(0, 500),
                promptLength: prompt.length,
                response: refinedReply.substring(0, 500),
                responseLength: refinedReply.length,
                model: "refined-pipeline",
                conversationHistoryLength: conversationHistory?.length || 0,
                timing: {
                    total: totalResponseTime,
                    chatgpt: chatgptTime,
                    claude: claudeTime,
                    fusion: 0,
                },
                tokens: {
                    total: totalTokens,
                    chatgpt: chatgptTokens,
                    claude: claudeTokens,
                    fusion: 0,
                },
                toneAdapted: toneAdapted,
                isImageGeneration: isImageReq,
                isPageScan: isPageScan,
                chatgptSuccess: true,
                claudeSuccess: Boolean(refinedReply),
                systemPrompt: system || null,
                mode: 'refined',
            }
                saveConversationLog(conversationLog)
                updateAnalytics({
                    messageCount: conversationHistory?.length || 0,
                    tokensUsed: totalTokens,
                    responseTime: totalResponseTime,
                    model: "refined-pipeline",
                    failed: false,
                    isImageGeneration: isImageReq,
                    isPageScan: isPageScan,
                    toneAdapted: toneAdapted,
                    userId: userIdentifier,
                    cost: totalCost,
                    openaiCost: openaiCost,
                    anthropicCost: anthropicCost,
                })
                
                res.json({
                    reply: refinedReply,
                    model: "refined-pipeline",
                    toneAdapted: toneAdapted,
                    citations: ragCitations.length > 0 ? ragCitations : undefined,
                    ragUsed: ragCitations.length > 0,
                    timing: {
                        total: totalResponseTime,
                        chatgpt: chatgptTime,
                        claude: claudeTime,
                    },
                    tokens: {
                        total: totalTokens,
                        chatgpt: chatgptTokens,
                        claude: claudeTokens,
                    }
                })
                log(`[Refined Mode] ===== REFINED MODE COMPLETED SUCCESSFULLY =====`)
                return
            } catch (refinedModeError) {
                // Extract full error details
                const errorMessage = refinedModeError.message || String(refinedModeError)
                const errorStatus = refinedModeError.status || refinedModeError.statusCode || refinedModeError.response?.status || ''
                const errorType = refinedModeError.type || refinedModeError.error?.type || ''
                const errorDetails = refinedModeError.error || refinedModeError.response?.data || {}
                
                // Log comprehensive error details
                log(`[Refined Mode] ===== REFINED MODE ERROR =====`, 'error')
                log(`[Refined Mode] Error message: ${errorMessage}`, 'error')
                log(`[Refined Mode] Error status: ${errorStatus}`, 'error')
                log(`[Refined Mode] Error type: ${errorType}`, 'error')
                log(`[Refined Mode] Error details: ${JSON.stringify(errorDetails, null, 2)}`, 'error')
                log(`[Refined Mode] Model used: claude-3-haiku-20240307 (Claude 3 Haiku)`, 'error')
                log(`[Refined Mode] Anthropic client available: ${anthropicClient ? 'YES' : 'NO'}`, 'error')
                log(`[Refined Mode] Anthropic API key configured: ${anthropicKey ? 'YES (length: ' + String(anthropicKey).length + ')' : 'NO - MISSING!'}`, 'error')
                if (anthropicKey) {
                    // Show first 10 and last 4 chars of API key for debugging (mask the middle)
                    const keyStr = String(anthropicKey)
                    const maskedKey = keyStr.length > 14 ? `${keyStr.substring(0, 10)}...${keyStr.substring(keyStr.length - 4)}` : '***'
                    log(`[Refined Mode] API key preview: ${maskedKey}`, 'error')
                }
                log(`[Refined Mode] ===== END ERROR =====`, 'error')
                
                // Check what type of error occurred - be more specific
                const isModelErr = (errorStatus === 404 || errorType === "not_found_error" || errorMessage.includes("not_found_error") || (errorMessage.includes("model:") && errorMessage.includes("not found")))
                const isAuthErr = (errorStatus === 401 || errorStatus === 403 || errorType === "authentication_error" || errorMessage.includes("authentication") || errorMessage.includes("api_key") || errorMessage.includes("unauthorized") || errorMessage.includes("Invalid API key"))
                const isNetworkErr = errorMessage.includes("timeout") || errorMessage.includes("ECONNREFUSED") || errorMessage.includes("network") || errorMessage.includes("ENOTFOUND")
                
                // Always provide fallback to ChatGPT if available
                if (chatgptReply) {
                    let userMessage = ""
                    
                    if (isAuthErr) {
                        log(`[Refined Mode] ⚠️  Claude API authentication error - check your ANTHROPIC_API_KEY`, 'error')
                        userMessage = "\n\n⚠️ Note: Claude refinement failed due to authentication error. This is ChatGPT's response only. Please check your ANTHROPIC_API_KEY in .env file."
                    } else if (isModelErr) {
                        log(`[Refined Mode] ⚠️  Claude API returned model error (this shouldn't happen - model is hardcoded correctly!)`, 'error')
                        log(`[Refined Mode] The API might be rejecting the request. Check your ANTHROPIC_API_KEY is valid.`, 'error')
                        userMessage = `\n\n⚠️ Note: Claude API returned "model not found" (404). Possible causes:\n1. Your ANTHROPIC_API_KEY doesn't have access to Claude 3 Haiku\n2. Your API key is invalid or expired\n3. Your API key format is incorrect\n\nPlease check your Anthropic dashboard and verify:\n- Your API key is valid and active\n- Your API key starts with "sk-ant-" and is correct\n- Your account has access to Claude 3 Haiku (claude-3-haiku-20240307)\n\nThis is ChatGPT's response only.`
                    } else {
                        log(`[Refined Mode] ⚠️  Claude API error (unknown type) - falling back to ChatGPT`, 'error')
                        userMessage = `\n\n⚠️ Note: Claude refinement failed. This is ChatGPT's response only. Error: ${errorMessage}`
                    }
                    
                    const totalResponseTime = Date.now() - requestStartTime
                    res.json({
                        reply: chatgptReply + userMessage,
                        model: "chatgpt-only-fallback",
                        warning: "Claude refinement failed - using ChatGPT response only",
                        error: errorMessage,
                        errorType: isAuthErr ? "authentication" : isModelErr ? "model" : "unknown"
                    })
                    return
                }
                
                // Return error instead of falling back to quick mode
                // User explicitly selected refined mode, so we should respect that
                const totalResponseTime = Date.now() - requestStartTime
                res.status(500).json({
                    error: "Refined mode failed",
                    message: refinedModeError.message || "An error occurred during the refinement process",
                    details: {
                        chatgptSuccess: chatgptReply ? true : false,
                        claudeSuccess: false,
                        mode: "refined"
                    }
                })
                return
            }
        }
        
        // QUICK MODE: Optimized parallel processing with caching
        log(`[Quick Mode] ===== STARTING OPTIMIZED QUICK MODE =====`)
        
        // STEP 1: Check cache first (instant responses for repeated queries)
        const cacheKey = generateCacheKey(prompt, recentHistory, system)
        const cachedResponse = getCachedResponse(cacheKey)
        
        if (cachedResponse) {
            const cacheTime = Date.now() - requestStartTime
            log(`[Quick Mode] ⚡ CACHE HIT! Returning cached response (${cacheTime}ms)`)
            res.json({
                reply: cachedResponse.reply,
                model: cachedResponse.model || "lumra-cached",
                cached: true,
                timing: {
                    total: cacheTime,
                    chatgpt: 0,
                    claude: 0,
                    fusion: 0,
                },
                tokens: {
                    total: 0,
                    chatgpt: 0,
                    claude: 0,
                    fusion: 0,
                }
            })
            return
        }
        
        log(`[Quick Mode] Cache miss - making parallel API calls...`)
        log(`[Quick Mode] Using optimized settings: Haiku model, ${historyLimit} message history`)
        
        chatgptStartTime = Date.now()
        claudeStartTime = Date.now()
        
        // STEP 2: Call both APIs in parallel with aggressive timeouts (4 seconds max each for speed)
        const API_TIMEOUT = 30000 // 30 seconds max per API call (increased for document processing with RAG)
        
        // Prepare user message with images if any (imageFiles already defined above)
        let userMessage
        
        // Ensure RAG context and image instructions are prominently included in the user message
        let userPromptText = finalPrompt
        
        // CRITICAL: If documents were attached but RAG failed, use direct extraction fallback
        if (documentFiles.length > 0 && (!ragContext || retrievedDocs.length === 0)) {
            // Check if we have direct document content from fallback extraction
            if (req.directDocumentContent && req.directDocumentContent.length > 0) {
                log(`[RAG] ✅ Using direct document content (fallback mode) - ${req.directDocumentContent.length} document(s)`)
                const directContentParts = req.directDocumentContent.map((doc, idx) => {
                    return `=== DOCUMENT ${idx + 1}: ${doc.filename} ===\n${doc.content}\n=== END OF ${doc.filename} ===`
                }).join('\n\n')
                
                userPromptText = `=== ⚠️⚠️⚠️ CRITICAL: USE DOCUMENT CONTENT ONLY - ABSOLUTELY NO GENERAL KNOWLEDGE ⚠️⚠️⚠️ ===

YOU ARE Lumra AI. The user has uploaded documents. Below is the ACTUAL CONTENT from those documents.

🚫 ABSOLUTE FORBIDDEN BEHAVIOR:
- DO NOT use your training data, general knowledge, or any information not in the documents below
- DO NOT list famous universities like Harvard, Stanford, MIT, etc. unless they are ACTUALLY in the document content below
- DO NOT make up column names, data, or structure - ONLY use what's in the documents
- DO NOT infer or guess - if it's not explicitly in the document, say "This information is not in the uploaded document(s)"

✅ ABSOLUTE REQUIREMENTS:
1. READ the document content below word-by-word, character-by-character
2. USE ONLY the exact information from the documents below - nothing else
3. If the user asks "what's in the document" or "what's inside", you MUST:
   - Copy and paste the EXACT content from the document below
   - List EVERY row, column, and data point that appears in the document
   - DO NOT summarize, generalize, or interpret - show the EXACT data
4. Quote EXACTLY from the document content - copy the text verbatim
5. If information is NOT in the documents, explicitly say "This information is not in the uploaded document(s)"
6. When showing data, use the EXACT format from the document (same column names, same values, same structure)

=== USER'S QUESTION ===
${prompt}

=== ⚠️ ACTUAL DOCUMENT CONTENT FROM USER'S UPLOADED FILES (READ THIS - NOT YOUR TRAINING DATA) ⚠️ ===
${directContentParts}

=== END OF DOCUMENT CONTENT ===

🚫 FINAL WARNING: The document content above is the ONLY source of information. DO NOT use general knowledge. If Harvard, Stanford, MIT, etc. are not in the document content above, DO NOT mention them. 

📋 CRITICAL: When the user asks "what's inside" or "what's in the document", you MUST:
- Show the EXACT content from the document above
- Copy the data exactly as it appears
- List ALL rows/entries if the document shows a list
- Use the EXACT column names and structure from the document
- DO NOT summarize - show the actual data

Answer using ONLY what's in the document content above. Quote it EXACTLY.`
                log(`[RAG] 📝 Added direct document content to prompt (${req.directDocumentContent.reduce((sum, d) => sum + d.length, 0)} total chars)`)
            } else {
                const docNames = documentFiles.map(f => f.name || 'document').join(', ')
                const docNote = `\n\n=== CRITICAL: USER HAS ATTACHED DOCUMENTS ===
The user has attached ${documentFiles.length} document(s) to this message: ${docNames}

IMPORTANT: The user has uploaded these files. Even if document processing encountered technical issues, you MUST acknowledge that documents were uploaded.

FORBIDDEN: NEVER say "I can't see documents", "I don't see any PDF", or "please upload again"
MANDATORY: Acknowledge the uploaded documents (${docNames}) and help the user with their question.

The user is asking about these documents they just uploaded.`
                userPromptText = userPromptText + docNote
                log(`[RAG] 📄 Added document attachment notice to prompt (${documentFiles.length} file(s))`)
            }
        }
        if (ragContext && retrievedDocs.length > 0) {
            // Make RAG context very explicit at the start with STRONG instructions
            // CRITICAL: Log what we're sending to verify content
            log(`[RAG] 🔍 SENDING TO AI: ${retrievedDocs.length} chunks, total context: ${ragContext.length} chars`)
            log(`[RAG] 📄 First 1000 chars of context being sent: "${ragContext.substring(0, 1000)}..."`)
            
            userPromptText = `=== ⚠️⚠️⚠️ CRITICAL: USE DOCUMENT CONTENT ONLY - ABSOLUTELY NO GENERAL KNOWLEDGE ⚠️⚠️⚠️ ===

YOU ARE Lumra AI. The user has uploaded documents. Below is the ACTUAL CONTENT from those documents.

🚫 ABSOLUTE FORBIDDEN BEHAVIOR:
- DO NOT use your training data, general knowledge, or any information not in the documents below
- DO NOT list famous universities like Harvard, Stanford, MIT, etc. unless they are ACTUALLY in the document content below
- DO NOT make up column names, data, or structure - ONLY use what's in the documents
- DO NOT infer or guess - if it's not explicitly in the document, say "This information is not in the uploaded document(s)"

✅ ABSOLUTE REQUIREMENTS:
1. READ the document content below word-by-word, character-by-character
2. USE ONLY the exact information from the documents below - nothing else
3. If the user asks "what's in the document" or "what's inside", you MUST:
   - Copy and paste the EXACT content from the document below
   - List EVERY row, column, and data point that appears in the document
   - DO NOT summarize, generalize, or interpret - show the EXACT data
4. Quote EXACTLY from the document content - copy the text verbatim
5. If information is NOT in the documents, explicitly say "This information is not in the uploaded document(s)"
6. When showing data, use the EXACT format from the document (same column names, same values, same structure)

=== USER'S QUESTION ===
${prompt}

=== ⚠️ ACTUAL DOCUMENT CONTENT FROM USER'S UPLOADED FILES (READ THIS - NOT YOUR TRAINING DATA) ⚠️ ===
${ragContext}

=== END OF DOCUMENT CONTENT ===

🚫 FINAL WARNING: The document content above is the ONLY source of information. DO NOT use general knowledge. If Harvard, Stanford, MIT, etc. are not in the document content above, DO NOT mention them. 

📋 CRITICAL: When the user asks "what's inside" or "what's in the document", you MUST:
- Show the EXACT content from the document above
- Copy the data exactly as it appears
- List ALL rows/entries if the document shows a list
- Use the EXACT column names and structure from the document
- DO NOT summarize - show the actual data

Answer using ONLY what's in the document content above. Quote it EXACTLY.`
            log(`[RAG] 📝 Enhanced user prompt with STRONG RAG context (${userPromptText.length} chars, ${retrievedDocs.length} chunks)`)
        } else if (hasDocuments && (!ragContext || retrievedDocs.length === 0)) {
            // User has documents but retrieval failed - still tell AI documents exist
            userPromptText = `=== CRITICAL INSTRUCTION: DOCUMENT ACCESS ===
YOU ARE Lumra AI. The user has uploaded documents.

FORBIDDEN: NEVER say "I can't read files" or "I can't access documents"

MANDATORY: Acknowledge that documents were uploaded and work with the user. Ask clarifying questions about what they need from their documents.

=== USER'S QUESTION ===
${prompt}

Note: Document content retrieval encountered an issue, but documents were uploaded. Help the user with their question.`
            log(`[RAG] ⚠️  User has documents but retrieval failed - added fallback message`)
        }
        
        // Add image analysis instruction if images are present
        if (hasImages && imageFiles.length > 0) {
            const imageNote = `\n\n=== IMAGE ANALYSIS REQUEST ===\nThe user has uploaded ${imageFiles.length} image(s) for you to analyze. Please examine the image(s) included in this message and provide a detailed analysis based on what you see.`
            userPromptText = userPromptText + imageNote
            log(`[Image Analysis] 📝 Added image analysis note to user prompt`)
        }
        
        if (imageFiles.length > 0) {
            // Include images in the message (ChatGPT vision API format)
            log(`[Image Analysis] 📸 Preparing ${imageFiles.length} image(s) for ChatGPT API`)
            
            // Validate image data before sending
            const validImageFiles = imageFiles.filter((file) => {
                if (!file.data || !file.type) {
                    log(`[Image Analysis] ⚠️  Skipping invalid image file: missing data or type`, 'error')
                    return false
                }
                // Check if data is base64 (starts with data: or is base64 string)
                const isBase64 = file.data.startsWith('data:') || /^[A-Za-z0-9+/=]+$/.test(file.data.substring(0, 100))
                if (!isBase64 && !file.data.startsWith('data:')) {
                    log(`[Image Analysis] ⚠️  Image data may not be in correct format for file: ${file.name}`, 'error')
                }
                return true
            })
            
            if (validImageFiles.length === 0) {
                log(`[Image Analysis] ❌ No valid image files found - falling back to text-only message`, 'error')
                userMessage = { role: "user", content: userPromptText }
            } else {
                log(`[Image Analysis] ✅ ${validImageFiles.length} valid image(s) ready to send`)
                userMessage = {
                    role: "user",
                    content: [
                        { type: "text", text: userPromptText },
                        ...validImageFiles.map((file) => {
                            // Ensure proper data URL format
                            const imageUrl = file.data.startsWith('data:') 
                                ? file.data 
                                : `data:${file.type};base64,${file.data}`
                            log(`[Image Analysis] 📷 Image: ${file.name || 'unnamed'} (${file.type}), data length: ${file.data.length} chars`)
                            return {
                                type: "image_url",
                                image_url: { url: imageUrl }
                            }
                        })
                    ]
                }
            }
        } else {
            userMessage = { role: "user", content: userPromptText }
        }
        
        // CRITICAL: Log what we're sending to ChatGPT
        if (ragContext && retrievedDocs.length > 0) {
            log(`[RAG] ✅ Sending RAG context to ChatGPT (${ragContext.length} chars, ${retrievedDocs.length} chunks)`)
            const userMsgText = typeof userMessage.content === 'string' ? userMessage.content : (userMessage.content?.[0]?.text || '')
            log(`[RAG] 📄 User message contains RAG: ${userMsgText.includes('DOCUMENT') || userMsgText.includes('RELEVANT DOCUMENTS')}`)
            log(`[RAG] 📄 User message preview: "${userMsgText.substring(0, 300)}..."`)
        } else if (hasDocuments) {
            log(`[RAG] ⚠️  CRITICAL: User has ${hasDocuments} document(s) but RAG context is EMPTY!`)
            log(`[RAG] ⚠️  This means retrieval failed - documents exist but can't be accessed`)
        } else {
            log(`[RAG] ℹ️  No documents uploaded by user yet`)
        }
        
        const chatgptPromise = Promise.race([
            openaiClient.chat.completions.create({
                model: process.env.OPENAI_MODEL || "gpt-4o-mini",
                temperature,
                max_tokens: 800, // Reduced tokens for faster response
                messages: [
                    ...(adaptiveSystemPrompt ? [{ role: "system", content: adaptiveSystemPrompt }] : []),
                    ...recentHistory,
                    userMessage,
                ],
            }),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error(`ChatGPT timeout after ${API_TIMEOUT/1000} seconds`)), API_TIMEOUT)
            )
        ])
        
        // Prepare Claude message with images if any (Claude 3 supports images)
        let claudeUserMessage
        // Use the same enhanced prompt with RAG context for Claude
        const claudePromptText = userPromptText || finalPrompt
        
        if (imageFiles.length > 0) {
            log(`[Image Analysis] 📸 Preparing ${imageFiles.length} image(s) for Claude API`)
            
            // Validate and prepare images for Claude
            const validClaudeImages = imageFiles.filter((file) => {
                if (!file.data || !file.type) {
                    log(`[Image Analysis] ⚠️  Skipping invalid image for Claude: missing data or type`, 'error')
                    return false
                }
                return true
            })
            
            if (validClaudeImages.length === 0) {
                log(`[Image Analysis] ❌ No valid images for Claude - using text-only message`, 'error')
                claudeUserMessage = { role: "user", content: claudePromptText }
            } else {
                log(`[Image Analysis] ✅ ${validClaudeImages.length} valid image(s) ready for Claude`)
                // Claude 3 API format for images (needs base64 WITHOUT data: prefix)
                claudeUserMessage = {
                    role: "user",
                    content: [
                        { type: "text", text: claudePromptText },
                        ...validClaudeImages.map((file) => {
                            // Extract base64 data (remove data:image/type;base64, prefix if present)
                            let base64Data = file.data
                            if (base64Data.startsWith('data:')) {
                                const base64Match = base64Data.match(/^data:[^;]+;base64,(.+)$/)
                                base64Data = base64Match ? base64Match[1] : base64Data.split(',')[1] || base64Data
                            }
                            
                            log(`[Image Analysis] 📷 Claude image: ${file.name || 'unnamed'} (${file.type}), base64 length: ${base64Data.length} chars`)
                            return {
                                type: "image",
                                source: {
                                    type: "base64",
                                    media_type: file.type,
                                    data: base64Data
                                }
                            }
                        })
                    ]
                }
            }
        } else {
            claudeUserMessage = { role: "user", content: claudePromptText }
        }
        
        // CRITICAL: Log what we're sending to Claude
        if (ragContext && retrievedDocs.length > 0) {
            log(`[RAG] ✅ Sending RAG context to Claude (${ragContext.length} chars, ${retrievedDocs.length} chunks)`)
            log(`[RAG] 📄 Claude message contains RAG: ${claudePromptText.includes('DOCUMENT') || (claudeUserMessage.content && typeof claudeUserMessage.content === 'string' && claudeUserMessage.content.includes('DOCUMENT'))}`)
        } else if (hasDocuments) {
            log(`[RAG] ⚠️  User has documents but RAG context is empty for Claude - this is a problem!`)
        }
        
        const claudePromise = Promise.race([
            anthropicClient.messages.create({
                model: claudeModel,
                temperature,
                max_tokens: 800, // Reduced tokens for faster response
                system: adaptiveSystemPrompt,
                messages: [
                    ...recentHistory.map((msg) => ({
                        role: msg.role === "assistant" ? "assistant" : "user",
                        content: msg.content,
                    })),
                    claudeUserMessage,
                ],
            }),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error(`Claude timeout after ${API_TIMEOUT/1000} seconds`)), API_TIMEOUT)
            )
        ])
        
        const [chatgptResult, claudeResult] = await Promise.allSettled([
            chatgptPromise,
            claudePromise
        ])

        chatgptEndTime = Date.now()
        claudeEndTime = Date.now()
        
        const chatgptTime = chatgptEndTime - chatgptStartTime
        const claudeTime = claudeEndTime - claudeStartTime
        
        let chatgptReply = ""
        let claudeReply = ""
        let chatgptTokens = 0
        let claudeTokens = 0

        if (chatgptResult.status === "fulfilled") {
            chatgptReply = chatgptResult.value.choices[0]?.message?.content?.trim() || ""
            chatgptTokens = chatgptResult.value.usage?.total_tokens || 0
            console.log(`[ChatGPT Response] (${chatgptReply.length} chars, ${chatgptTokens} tokens, ${chatgptTime}ms)`)
            console.log(chatgptReply.substring(0, 200) + (chatgptReply.length > 200 ? "..." : ""))
        } else {
            const chatgptError = chatgptResult.reason
            const chatgptErrorMessage = chatgptError?.message || chatgptError?.error?.message || "Unknown error"
            const chatgptErrorType = chatgptError?.error?.type || chatgptError?.constructor?.name || "unknown"
            console.log(`[ChatGPT Response] FAILED: ${chatgptErrorMessage} (${chatgptTime}ms)`)
            console.log(`[ChatGPT Error Type] ${chatgptErrorType}`)
            if (chatgptError?.stack) {
                console.log(`[ChatGPT Error Stack] ${chatgptError.stack.substring(0, 500)}`)
            }
            log(`[ChatGPT] ❌ Failed: ${chatgptErrorMessage}`, "error")
        }

        if (claudeResult.status === "fulfilled") {
            claudeReply = claudeResult.value.content
                ?.map((block) => ("text" in block ? block.text : ""))
                .join("\n")
                .trim() || ""
            claudeTokens = claudeResult.value.usage?.input_tokens + claudeResult.value.usage?.output_tokens || 0
            console.log(`[Claude Response] ✅ SUCCESS (${claudeReply.length} chars, ${claudeTokens} tokens, ${claudeTime}ms)`)
            console.log(claudeReply.substring(0, 200) + (claudeReply.length > 200 ? "..." : ""))
        } else {
            const errorDetails = claudeResult.reason
            const errorMessage = errorDetails?.message || errorDetails?.error?.message || "Unknown error"
            const errorType = errorDetails?.error?.type || errorDetails?.constructor?.name || "unknown"
            console.log(`[Claude Response] ❌ FAILED: ${errorMessage} (${claudeTime}ms)`)
            console.log(`[Claude Error Type] ${errorType}`)
            if (errorDetails?.stack) {
                console.log(`[Claude Error Stack] ${errorDetails.stack.substring(0, 500)}`)
            }
            log(`[Claude] ❌ Failed: ${errorMessage}`, "error")
            if (errorType === "not_found_error") {
                console.log(`[Claude Model Issue] Current model: ${process.env.ANTHROPIC_MODEL || "claude-3-5-sonnet-20240620"}`)
                console.log(`[Claude Model Issue] ⚠️  The model name in your .env file may be incorrect!`)
                console.log(`[Claude Model Issue] Valid models: claude-3-5-sonnet-20240620, claude-3-opus-20240229, claude-3-sonnet-20240229, claude-3-haiku-20240307`)
            }
        }

        // If both failed, return error
        if (!chatgptReply && !claudeReply) {
            const totalResponseTime = Date.now() - requestStartTime
            console.log(`[ERROR] Both AI services failed (${totalResponseTime}ms)`)
            console.log("=".repeat(80))
            console.log("")
            
            // Save failed log
            const conversationLog = {
                id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                timestamp: new Date().toISOString(),
                userId: userIdentifier,
                prompt: prompt.substring(0, 500),
                promptLength: prompt.length,
                response: null,
                responseLength: 0,
                model: "failed",
                conversationHistoryLength: conversationHistory?.length || 0,
                timing: {
                    total: totalResponseTime,
                    chatgpt: chatgptTime,
                    claude: claudeTime,
                    fusion: 0,
                },
                tokens: {
                    total: 0,
                    chatgpt: 0,
                    claude: 0,
                    fusion: 0,
                },
                toneAdapted: toneAdapted,
                isImageGeneration: isImageReq,
                isPageScan: isPageScan,
                chatgptSuccess: false,
                claudeSuccess: false,
                error: {
                    chatgpt: chatgptResult.status === "rejected" ? chatgptResult.reason?.message : null,
                    claude: claudeResult.status === "rejected" ? claudeResult.reason?.message : null,
                },
                systemPrompt: system || null,
            }
            saveConversationLog(conversationLog)
            updateAnalytics({
                messageCount: conversationHistory?.length || 0,
                tokensUsed: 0,
                responseTime: totalResponseTime,
                model: "failed",
                failed: true,
                isImageGeneration: isImageReq,
                isPageScan: isPageScan,
                toneAdapted: toneAdapted,
                userId: userIdentifier,
            })
            
            res.status(500).json({
                error: "Both AI services failed",
                details: {
                    chatgpt: chatgptResult.status === "rejected" ? chatgptResult.reason?.message : null,
                    claude: claudeResult.status === "rejected" ? claudeResult.reason?.message : null,
                },
            })
            return
        }

        // If only one succeeded, return that one
        if (!chatgptReply && claudeReply) {
            const totalResponseTime = Date.now() - requestStartTime
            const totalTokens = claudeTokens
            
            // Calculate cost
            let anthropicCost = 0
            if (claudeResult.status === "fulfilled" && claudeResult.value.usage) {
                const currentClaudeModel = claudeModel || process.env.ANTHROPIC_MODEL || "claude-3-haiku-20240307"
                const claudeModelName = getModelName(currentClaudeModel)
                const inputTokens = claudeResult.value.usage.input_tokens || 0
                const outputTokens = claudeResult.value.usage.output_tokens || 0
                anthropicCost = calculateTokenCost(claudeModelName, inputTokens, outputTokens)
            }
            
            console.log(`[Lumra AI Final Response] (Claude only - ${claudeReply.length} chars, ${totalTokens} tokens)`)
            console.log(`[Cost] Anthropic: $${anthropicCost.toFixed(6)}`)
            console.log(`[Timing] Claude: ${claudeTime}ms | Total: ${totalResponseTime}ms`)
            console.log(`[Tone Adaptation] ${toneAdapted ? "✅ Active" : "❌ Not active"}`)
            console.log(claudeReply.substring(0, 300) + (claudeReply.length > 300 ? "..." : ""))
            console.log("=".repeat(80))
            console.log("")
            
            // Save log
            const conversationLog = {
                id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                timestamp: new Date().toISOString(),
                userId: userIdentifier,
                prompt: prompt.substring(0, 500),
                promptLength: prompt.length,
                response: claudeReply.substring(0, 500),
                responseLength: claudeReply.length,
                model: "claude-only",
                conversationHistoryLength: conversationHistory?.length || 0,
                timing: {
                    total: totalResponseTime,
                    chatgpt: 0,
                    claude: claudeTime,
                    fusion: 0,
                },
                tokens: {
                    total: totalTokens,
                    chatgpt: 0,
                    claude: claudeTokens,
                    fusion: 0,
                },
                toneAdapted: toneAdapted,
                isImageGeneration: isImageReq,
                isPageScan: isPageScan,
                chatgptSuccess: false,
                claudeSuccess: true,
                systemPrompt: system || null,
            }
            saveConversationLog(conversationLog)
            updateAnalytics({
                messageCount: conversationHistory?.length || 0,
                tokensUsed: totalTokens,
                responseTime: totalResponseTime,
                model: "claude-only",
                failed: false,
                isImageGeneration: isImageReq,
                isPageScan: isPageScan,
                toneAdapted: toneAdapted,
                userId: userIdentifier,
                cost: anthropicCost,
                anthropicCost: anthropicCost,
            })
            
            res.json({ 
                reply: claudeReply, 
                model: "claude-only",
                citations: ragCitations.length > 0 ? ragCitations : undefined,
                ragUsed: ragCitations.length > 0,
            })
            return
        }
        if (chatgptReply && !claudeReply) {
            const totalResponseTime = Date.now() - requestStartTime
            const totalTokens = chatgptTokens
            
            // Calculate cost
            let openaiCost = 0
            if (chatgptResult.status === "fulfilled" && chatgptResult.value.usage) {
                const chatgptModel = getModelName(process.env.OPENAI_MODEL || "gpt-4o-mini")
                const inputTokens = chatgptResult.value.usage.prompt_tokens || 0
                const outputTokens = chatgptResult.value.usage.completion_tokens || 0
                openaiCost = calculateTokenCost(chatgptModel, inputTokens, outputTokens)
            }
            
            console.log(`[Lumra AI Final Response] (ChatGPT only - ${chatgptReply.length} chars, ${totalTokens} tokens)`)
            console.log(`[Cost] OpenAI: $${openaiCost.toFixed(6)}`)
            console.log(`[Timing] ChatGPT: ${chatgptTime}ms | Total: ${totalResponseTime}ms`)
            console.log(`[Tone Adaptation] ${toneAdapted ? "✅ Active" : "❌ Not active"}`)
            console.log(chatgptReply.substring(0, 300) + (chatgptReply.length > 300 ? "..." : ""))
            console.log("=".repeat(80))
            console.log("")
            
            // Save log
            const conversationLog = {
                id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                timestamp: new Date().toISOString(),
                userId: userIdentifier,
                prompt: prompt.substring(0, 500),
                promptLength: prompt.length,
                response: chatgptReply.substring(0, 500),
                responseLength: chatgptReply.length,
                model: "chatgpt-only",
                conversationHistoryLength: conversationHistory?.length || 0,
                timing: {
                    total: totalResponseTime,
                    chatgpt: chatgptTime,
                    claude: 0,
                    fusion: 0,
                },
                tokens: {
                    total: totalTokens,
                    chatgpt: chatgptTokens,
                    claude: 0,
                    fusion: 0,
                },
                toneAdapted: toneAdapted,
                isImageGeneration: isImageReq,
                isPageScan: isPageScan,
                chatgptSuccess: true,
                claudeSuccess: false,
                systemPrompt: system || null,
            }
            saveConversationLog(conversationLog)
            updateAnalytics({
                messageCount: conversationHistory?.length || 0,
                tokensUsed: totalTokens,
                responseTime: totalResponseTime,
                model: "chatgpt-only",
                failed: false,
                isImageGeneration: isImageReq,
                isPageScan: isPageScan,
                toneAdapted: toneAdapted,
                userId: userIdentifier,
                cost: openaiCost,
                openaiCost: openaiCost,
            })
            
            res.json({ 
                reply: chatgptReply, 
                model: "chatgpt-only",
                citations: ragCitations.length > 0 ? ragCitations : undefined,
                ragUsed: ragCitations.length > 0,
            })
            return
        }

        // Both succeeded - Smart fusion with similarity check (QUICK MODE OPTIMIZATION)
        log(`[Quick Mode] Both responses received. Checking similarity...`)
        
        // STEP 3: Calculate similarity to decide if fusion is needed
        let similarity = 0
        if (chatgptReply && claudeReply) {
            similarity = calculateSimilarity(chatgptReply, claudeReply)
            log(`[Quick Mode] Response similarity: ${(similarity * 100).toFixed(1)}%`)
        } else {
            log(`[Quick Mode] ⚠️  Cannot calculate similarity - one response missing`)
        }
        
        let fusedReply = ""
        let fusionTime = 0
        let fusionTokens = 0
        let finalReply = ""
        let finalModel = ""
        let fusionCompletion = null
        
        // STEP 4: Aggressive smart fusion - skip fusion more often for speed
        // QUICK MODE OPTIMIZATION: Only use fusion if responses are VERY different
        // INCREASED THRESHOLD: Skip fusion more often for speed (was 0.75, now 0.65)
        if (similarity > 0.65) {
            // Responses are similar enough - skip fusion API call (saves 2-5 seconds!)
            log(`[Quick Mode] ⚡ Responses are similar (${(similarity * 100).toFixed(1)}%) - skipping fusion API call`)
            log(`[Quick Mode] ⚡ Using client-side merge instead (saves 2-5 seconds)`)
            
            fusedReply = mergeResponsesClientSide(chatgptReply, claudeReply)
            fusionTime = 0 // No API call made
            fusionTokens = 0 // No tokens used for fusion
            finalReply = fusedReply || chatgptReply || claudeReply
            finalModel = "lumra-merged-client" // Indicates client-side merge
        } else if (similarity > 0.3) {
            // Medium similarity - quick client-side merge (faster than API fusion)
            // LOWERED THRESHOLD: More responses use fast merge (was 0.5, now 0.3)
            log(`[Quick Mode] ⚡ Medium similarity (${(similarity * 100).toFixed(1)}%) - using fast client-side merge`)
            fusedReply = mergeResponsesClientSide(chatgptReply, claudeReply)
            fusionTime = 0
            fusionTokens = 0
            finalReply = fusedReply || chatgptReply || claudeReply
            finalModel = "lumra-merged-fast"
        } else {
            // Responses differ significantly - use fusion API call
            log(`[Quick Mode] Responses differ (${(similarity * 100).toFixed(1)}% similar) - using fusion API call`)
            fusionStartTime = Date.now()
            
            // OPTIMIZATION: Aggressively limit response lengths for fastest fusion
            const maxFusionLength = 800 // Further reduced to 800 chars each for much faster fusion
            const truncatedChatgpt = chatgptReply.length > maxFusionLength 
                ? chatgptReply.substring(0, maxFusionLength) + "..."
                : chatgptReply
            const truncatedClaude = claudeReply.length > maxFusionLength
                ? claudeReply.substring(0, maxFusionLength) + "..."
                : claudeReply
            
            const fusionPrompt = `Combine these two AI responses into one clear answer. Be concise (under 500 words).

ChatGPT: ${truncatedChatgpt}
Claude: ${truncatedClaude}

CRITICAL: You are Lumra AI. When combining responses:
- Always identify as Lumra AI
- NEVER mention "ChatGPT", "Claude", or any AI model names
- NEVER say "Here is a combined answer" or similar phrases
- Simply provide the refined response directly as Lumra AI
- If asked "who made you" or "who created you", mention that you were created by developer Darsh Vekaria

Combined answer:`

            try {
                // Check if OpenAI client is available before attempting fusion
                if (!openaiClient) {
                    throw new Error("OpenAI client not initialized - check OPENAI_API_KEY in .env")
                }
                
                fusionCompletion = await Promise.race([
                    openaiClient.chat.completions.create({
                        model: process.env.OPENAI_MODEL || "gpt-4o-mini",
                        temperature: 0.5,
                        max_tokens: 500, // Further reduced to 500 tokens for faster response
                        messages: [
                            ...(adaptiveSystemPrompt ? [{ role: "system", content: adaptiveSystemPrompt }] : [{
                                role: "system",
                                content: "You are Lumra AI. You synthesize AI responses concisely. Always identify as Lumra AI. Never mention ChatGPT, Claude, or other AI models.",
                            }]),
                            { role: "user", content: fusionPrompt },
                        ],
                    }),
                    new Promise((_, reject) => 
                        setTimeout(() => reject(new Error("Fusion timeout after 35 seconds")), 35000) // Increased to 35 seconds for document processing
                    )
                ])
                
                fusionEndTime = Date.now()
                fusionTime = fusionEndTime - fusionStartTime
                fusionTokens = fusionCompletion.usage?.total_tokens || 0
                fusedReply = fusionCompletion.choices[0]?.message?.content?.trim() || ""
                finalReply = fusedReply || chatgptReply || claudeReply
                finalModel = fusedReply ? "lumra-fused" : (chatgptReply ? "chatgpt-only" : "claude-only")
                
                log(`[Quick Mode] ✅ Fusion completed in ${fusionTime}ms`)
            } catch (fusionError) {
                const errorMsg = fusionError.message || "Unknown error"
                log(`[Quick Mode] ⚠️  Fusion API call failed or timed out: ${errorMsg}`, 'error')
                
                // Check if it's an API key issue
                if (errorMsg.includes("API key") || errorMsg.includes("authentication") || errorMsg.includes("not initialized")) {
                    log(`[Quick Mode] ❌ OpenAI API key issue detected. Please check OPENAI_API_KEY in .env file`, 'error')
                }
                
                log(`[Quick Mode] ⚡ Falling back to client-side merge (this is normal if fusion times out)`)
                // Fallback to client-side merge if fusion fails
                fusedReply = mergeResponsesClientSide(chatgptReply, claudeReply)
                fusionTime = 0
                fusionTokens = 0
                finalReply = fusedReply || chatgptReply || claudeReply
                finalModel = "lumra-merged-fallback"
            }
        }
        
        const totalTokens = chatgptTokens + claudeTokens + fusionTokens
        const totalResponseTime = Date.now() - requestStartTime

        // Calculate costs
        let openaiCost = 0
        let anthropicCost = 0
        let fusionCost = 0
        
        if (chatgptResult.status === "fulfilled" && chatgptResult.value.usage) {
            const chatgptModel = getModelName(process.env.OPENAI_MODEL || "gpt-4o-mini")
            const inputTokens = chatgptResult.value.usage.prompt_tokens || 0
            const outputTokens = chatgptResult.value.usage.completion_tokens || 0
            openaiCost = calculateTokenCost(chatgptModel, inputTokens, outputTokens)
        }
        
        if (claudeResult.status === "fulfilled" && claudeResult.value.usage) {
            const currentClaudeModel = claudeModel || process.env.ANTHROPIC_MODEL || "claude-3-haiku-20240307"
            const claudeModelName = getModelName(currentClaudeModel)
            const inputTokens = claudeResult.value.usage.input_tokens || 0
            const outputTokens = claudeResult.value.usage.output_tokens || 0
            anthropicCost = calculateTokenCost(claudeModelName, inputTokens, outputTokens)
        }
        
        if (fusionTokens > 0 && fusionCompletion && fusionCompletion.usage) {
            const fusionModel = getModelName(process.env.OPENAI_MODEL || "gpt-4o-mini")
            const inputTokens = fusionCompletion.usage.prompt_tokens || 0
            const outputTokens = fusionCompletion.usage.completion_tokens || 0
            fusionCost = calculateTokenCost(fusionModel, inputTokens, outputTokens)
        }
        
        const totalCost = openaiCost + anthropicCost + fusionCost

        // STEP 5: Cache the result for future queries
        setCachedResponse(cacheKey, {
            reply: finalReply,
            model: finalModel
        })
        log(`[Quick Mode] ✅ Response cached for future queries`)
        
        // Log final response with timing
        log(`[Quick Mode] ===== QUICK MODE COMPLETED =====`)
        log(`[Quick Mode] Final Response: ${finalReply.length} chars, ${totalTokens} tokens`)
        log(`[Quick Mode] Cost: OpenAI: $${openaiCost.toFixed(6)}, Anthropic: $${anthropicCost.toFixed(6)}, Fusion: $${fusionCost.toFixed(6)}, Total: $${totalCost.toFixed(6)}`)
        log(`[Quick Mode] Timing: ChatGPT: ${chatgptTime}ms | Claude: ${claudeTime}ms | Fusion: ${fusionTime}ms | Total: ${totalResponseTime}ms`)
        log(`[Quick Mode] Similarity: ${(similarity * 100).toFixed(1)}% | Fusion skipped: ${similarity > 0.85 ? 'YES ✅' : 'NO'}`)
        log(`[Quick Mode] Tone Adaptation: ${toneAdapted ? "✅ Active" : "❌ Not active"}`)
        log(`[Quick Mode] Response preview: ${finalReply.substring(0, 300)}${finalReply.length > 300 ? "..." : ""}`)
        console.log("=".repeat(80))
        console.log("")

        // Store conversation in user profile for future analysis
        if (userIdentifier && conversationHistory) {
            const profile = userProfiles.get(userIdentifier) || { tone: null, preferences: null, messageCount: 0 }
            profile.messageCount = Math.max(profile.messageCount, conversationHistory.filter((msg) => msg.role === "user").length)
            userProfiles.set(userIdentifier, profile)
        }

        // Save conversation log
        const conversationLog = {
            id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            timestamp: new Date().toISOString(),
            userId: userIdentifier,
            prompt: prompt.substring(0, 500), // Store first 500 chars
            promptLength: prompt.length,
            response: finalReply.substring(0, 500), // Store first 500 chars
            responseLength: finalReply.length,
            model: finalModel,
            conversationHistoryLength: conversationHistory?.length || 0,
            timing: {
                total: totalResponseTime,
                chatgpt: chatgptTime,
                claude: claudeTime,
                fusion: fusionTime,
            },
            tokens: {
                total: totalTokens,
                chatgpt: chatgptTokens,
                claude: claudeTokens,
                fusion: fusionTokens,
            },
            toneAdapted: toneAdapted,
            isImageGeneration: isImageReq,
            isPageScan: isPageScan,
            chatgptSuccess: chatgptResult.status === "fulfilled",
            claudeSuccess: claudeResult.status === "fulfilled",
            systemPrompt: system || null,
        }
        saveConversationLog(conversationLog)

        // Update analytics
        updateAnalytics({
            messageCount: conversationHistory?.length || 0,
            tokensUsed: totalTokens,
            responseTime: totalResponseTime,
            model: finalModel,
            failed: !chatgptReply && !claudeReply,
            isImageGeneration: isImageReq,
            isPageScan: isPageScan,
            toneAdapted: toneAdapted,
            userId: userIdentifier,
            cost: totalCost,
            openaiCost: openaiCost,
            anthropicCost: anthropicCost,
        })

        res.json({
            reply: finalReply,
            model: finalModel,
            userId: userIdentifier,
            toneAdapted: toneAdapted,
            citations: ragCitations.length > 0 ? ragCitations : undefined,
            ragUsed: ragCitations.length > 0,
        })
    } catch (error) {
        const totalResponseTime = Date.now() - requestStartTime
        console.error("")
        console.error("[ERROR] Fusion error:", error.message, `(${totalResponseTime}ms)`)
        console.error("=".repeat(80))
        console.error("")
        
        // Save error log
        const conversationLog = {
            id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            timestamp: new Date().toISOString(),
            userId: userIdentifier,
            prompt: prompt.substring(0, 500),
            promptLength: prompt.length,
            response: null,
            responseLength: 0,
            model: "error",
            conversationHistoryLength: conversationHistory?.length || 0,
            timing: {
                total: totalResponseTime,
                chatgpt: chatgptTime || 0,
                claude: claudeTime || 0,
                fusion: 0,
            },
            tokens: {
                total: 0,
                chatgpt: chatgptTokens || 0,
                claude: claudeTokens || 0,
                fusion: 0,
            },
            toneAdapted: toneAdapted,
            isImageGeneration: isImageReq,
            isPageScan: isPageScan,
            chatgptSuccess: chatgptResult?.status === "fulfilled",
            claudeSuccess: claudeResult?.status === "fulfilled",
            error: error.message,
            systemPrompt: system || null,
        }
        saveConversationLog(conversationLog)
        updateAnalytics({
            messageCount: conversationHistory?.length || 0,
            tokensUsed: 0,
            responseTime: totalResponseTime,
            model: "error",
            failed: true,
            isImageGeneration: isImageReq,
            isPageScan: isPageScan,
            toneAdapted: toneAdapted,
            userId: userIdentifier,
        })
        
        res.status(500).json({ error: "Failed to combine AI responses", details: error.message })
    }
})

// Analytics endpoint - Get all analytics
app.get("/api/analytics", authenticateToken, (req, res) => {
    try {
        const analytics = loadAnalytics()
        const logs = loadConversationLogs()
        
        // Calculate additional stats
        const recentLogs = logs.slice(-100) // Last 100 conversations
        const successRate = logs.length > 0 
            ? Math.round((logs.filter(log => log.model !== "failed" && log.model !== "error").length / logs.length) * 100)
            : 0
        
        const avgTokensPerRequest = logs.length > 0
            ? Math.round(logs.reduce((sum, log) => sum + (log.tokens?.total || 0), 0) / logs.length)
            : 0
        
        const toneAdaptedCount = logs.filter(log => log.toneAdapted).length
        const toneAdaptationPercentage = logs.length > 0
            ? Math.round((toneAdaptedCount / logs.length) * 100)
            : 0
        
        res.json({
            success: true,
            analytics: {
                ...analytics,
                successRate,
                avgTokensPerRequest,
                toneAdaptationPercentage,
                totalLogs: logs.length,
            },
            recentActivity: recentLogs.slice(-10).map(log => ({
                id: log.id,
                timestamp: log.timestamp,
                userId: log.userId,
                model: log.model,
                responseTime: log.timing?.total || 0,
                tokens: log.tokens?.total || 0,
                toneAdapted: log.toneAdapted,
                isImageGeneration: log.isImageGeneration,
                isPageScan: log.isPageScan,
            })),
        })
    } catch (error) {
        console.error("Error fetching analytics:", error)
        res.status(500).json({ error: "Failed to fetch analytics", details: error.message })
    }
})

// Conversation logs endpoint - Get all conversation logs
app.get("/api/logs", authenticateToken, (req, res) => {
    try {
        const { limit = 100, offset = 0, userId, model, toneAdapted } = req.query
        let logs = loadConversationLogs()
        
        // Filter by userId if provided
        if (userId) {
            logs = logs.filter(log => log.userId === userId)
        }
        
        // Filter by model if provided
        if (model) {
            logs = logs.filter(log => log.model === model)
        }
        
        // Filter by toneAdapted if provided
        if (toneAdapted !== undefined) {
            const adapted = toneAdapted === "true"
            logs = logs.filter(log => log.toneAdapted === adapted)
        }
        
        // Sort by timestamp (newest first)
        logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        
        // Apply pagination
        const total = logs.length
        const paginatedLogs = logs.slice(Number(offset), Number(offset) + Number(limit))
        
        res.json({
            success: true,
            total,
            limit: Number(limit),
            offset: Number(offset),
            logs: paginatedLogs,
        })
    } catch (error) {
        console.error("Error fetching logs:", error)
        res.status(500).json({ error: "Failed to fetch logs", details: error.message })
    }
})

// Chart data endpoints for analytics graphs
app.get("/api/analytics/charts", requireDeveloperAuth, (req, res) => {
    try {
        const analytics = loadAnalytics()
        const logs = loadConversationLogs()
        
        // Time-based data (last 24 hours, hourly breakdown)
        const now = new Date()
        const last24Hours = Array.from({ length: 24 }, (_, i) => {
            const hour = new Date(now.getTime() - (23 - i) * 60 * 60 * 1000)
            return {
                hour: hour.getHours(),
                date: hour.toISOString().split('T')[0],
                hourLabel: hour.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
            }
        })
        
        const hourlyData = last24Hours.map(({ hour, date }) => {
            const hourStart = new Date(`${date}T${String(hour).padStart(2, '0')}:00:00`)
            const hourEnd = new Date(hourStart.getTime() + 60 * 60 * 1000)
            
            const hourLogs = logs.filter(log => {
                try {
                    const logTime = new Date(log.timestamp)
                    return logTime >= hourStart && logTime < hourEnd
                } catch {
                    return false
                }
            })
            
            return {
                hour: hour,
                label: `${String(hour).padStart(2, '0')}:00`,
                requests: hourLogs.length,
                tokens: hourLogs.reduce((sum, log) => sum + (log.tokens?.total || 0), 0),
                avgResponseTime: hourLogs.length > 0
                    ? Math.round(hourLogs.reduce((sum, log) => sum + (log.timing?.total || 0), 0) / hourLogs.length)
                    : 0,
                cost: hourLogs.reduce((sum, log) => sum + (log.cost || 0), 0)
            }
        })
        
        // Daily data (last 7 days)
        const last7Days = Array.from({ length: 7 }, (_, i) => {
            const date = new Date(now.getTime() - (6 - i) * 24 * 60 * 60 * 1000)
            return date.toISOString().split('T')[0]
        })
        
        const dailyData = last7Days.map(date => {
            const dayStart = new Date(`${date}T00:00:00`)
            const dayEnd = new Date(dayStart.getTime() + 24 * 60 * 60 * 1000)
            
            const dayLogs = logs.filter(log => {
                const logTime = new Date(log.timestamp)
                return logTime >= dayStart && logTime < dayEnd
            })
            
            return {
                date: date,
                label: new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
                requests: dayLogs.length,
                tokens: dayLogs.reduce((sum, log) => sum + (log.tokens?.total || 0), 0),
                avgResponseTime: dayLogs.length > 0
                    ? Math.round(dayLogs.reduce((sum, log) => sum + (log.timing?.total || 0), 0) / dayLogs.length)
                    : 0,
                cost: dayLogs.reduce((sum, log) => sum + (log.cost || 0), 0),
                chatgpt: dayLogs.filter(log => log.model === 'chatgpt-only' || log.model === 'lumra-fused' || log.model === 'lumra-merged-client' || log.model === 'lumra-merged-fast' || log.model === 'lumra-merged-fallback').length,
                claude: dayLogs.filter(log => log.model === 'claude-only' || log.model === 'lumra-fused' || log.model === 'lumra-merged-client' || log.model === 'lumra-merged-fast' || log.model === 'lumra-merged-fallback').length,
                fused: dayLogs.filter(log => log.model === 'lumra-fused' || log.model === 'lumra-merged-client' || log.model === 'lumra-merged-fast' || log.model === 'lumra-merged-fallback').length
            }
        })
        
        // Model usage breakdown
        const modelBreakdown = {
            chatgpt: analytics.chatgptCalls || 0,
            claude: analytics.claudeCalls || 0,
            fused: analytics.fusedCalls || 0,
            failed: analytics.failedCalls || 0
        }
        
        // Response time distribution (buckets)
        const responseTimeBuckets = [
            { label: '0-1s', min: 0, max: 1000 },
            { label: '1-2s', min: 1000, max: 2000 },
            { label: '2-5s', min: 2000, max: 5000 },
            { label: '5-10s', min: 5000, max: 10000 },
            { label: '10-20s', min: 10000, max: 20000 },
            { label: '20s+', min: 20000, max: Infinity }
        ]
        
        const responseTimeDistribution = responseTimeBuckets.map(bucket => ({
            label: bucket.label,
            count: analytics.responseTimes.filter(rt => rt >= bucket.min && rt < bucket.max).length
        }))
        
        // Cost breakdown by provider
        const costBreakdown = {
            openai: analytics.openaiCost || 0,
            anthropic: analytics.anthropicCost || 0,
            total: analytics.totalCost || 0
        }
        
        // Feature usage breakdown
        const featureUsage = {
            imageGenerations: analytics.imageGenerations || 0,
            pageScans: analytics.pageScans || 0,
            regularChats: (analytics.totalConversations || 0) - (analytics.imageGenerations || 0) - (analytics.pageScans || 0)
        }
        
        // Recent response times (last 50 for trend)
        const recentResponseTimes = analytics.responseTimes.slice(-50).map((rt, index) => ({
            index: index + 1,
            time: rt
        }))
        
        res.json({
            success: true,
            charts: {
                hourlyUsage: hourlyData,
                dailyUsage: dailyData,
                modelBreakdown: modelBreakdown,
                responseTimeDistribution: responseTimeDistribution,
                costBreakdown: costBreakdown,
                featureUsage: featureUsage,
                recentResponseTimes: recentResponseTimes
            }
        })
    } catch (error) {
        console.error("Error fetching chart data:", error)
        res.status(500).json({ error: "Failed to fetch chart data", details: error.message })
    }
})

// ============================================================================
// CONVERSATION STORAGE FUNCTIONS (User-specific)
// ============================================================================

// Load all conversations from file
function loadConversations() {
    if (existsSync(CONVERSATIONS_FILE)) {
        try {
            const data = readFileSync(CONVERSATIONS_FILE, "utf-8")
            return JSON.parse(data)
        } catch (error) {
            console.error("Error loading conversations:", error)
            return {}
        }
    }
    return {}
}

// Save all conversations to file
function saveConversations(conversations) {
    try {
        writeFileSync(CONVERSATIONS_FILE, JSON.stringify(conversations, null, 2), "utf-8")
    } catch (error) {
        console.error("Error saving conversations:", error)
        throw error
    }
}

// Get conversations for a specific user (by email)
function getUserConversations(userEmail) {
    const allConversations = loadConversations()
    return allConversations[userEmail] || []
}

// Save conversations for a specific user (by email)
function saveUserConversations(userEmail, conversations) {
    const allConversations = loadConversations()
    allConversations[userEmail] = conversations
    saveConversations(allConversations)
}

// ============================================================================
// CONVERSATION API ENDPOINTS
// ============================================================================

// GET all conversations for the authenticated user
app.get("/api/conversations", authenticateToken, (req, res) => {
    try {
        const userEmail = req.user.email
        if (!userEmail) {
            return res.status(400).json({
                success: false,
                error: "User email not found in token"
            })
        }
        
        const conversations = getUserConversations(userEmail)
        
        // Sort by updatedAt (most recent first)
        const sortedConversations = conversations.sort((a, b) => {
            return (b.updatedAt || 0) - (a.updatedAt || 0)
        })
        
        res.json({
            success: true,
            conversations: sortedConversations,
            count: sortedConversations.length
        })
    } catch (error) {
        console.error("Error fetching conversations:", error)
        res.status(500).json({
            success: false,
            error: "Failed to fetch conversations",
            details: error.message
        })
    }
})

// POST - Save or update a conversation
app.post("/api/conversations", authenticateToken, (req, res) => {
    try {
        const userEmail = req.user.email
        if (!userEmail) {
            return res.status(400).json({
                success: false,
                error: "User email not found in token"
            })
        }
        
        const { id, title, messages, createdAt, updatedAt } = req.body
        
        if (!id || !Array.isArray(messages)) {
            return res.status(400).json({
                success: false,
                error: "Invalid conversation data. 'id' and 'messages' array are required."
            })
        }
        
        const conversations = getUserConversations(userEmail)
        
        // Check if conversation exists
        const existingIndex = conversations.findIndex(conv => conv.id === id)
        
        const conversation = {
            id,
            title: title || "New Conversation",
            messages,
            createdAt: createdAt || Date.now(),
            updatedAt: updatedAt || Date.now()
        }
        
        if (existingIndex >= 0) {
            // Update existing conversation
            conversations[existingIndex] = conversation
        } else {
            // Add new conversation
            conversations.push(conversation)
        }
        
        // Keep only last 50 conversations per user
        const trimmedConversations = conversations.slice(-50)
        
        saveUserConversations(userEmail, trimmedConversations)
        
        res.json({
            success: true,
            conversation,
            message: existingIndex >= 0 ? "Conversation updated" : "Conversation saved"
        })
    } catch (error) {
        console.error("Error saving conversation:", error)
        res.status(500).json({
            success: false,
            error: "Failed to save conversation",
            details: error.message
        })
    }
})

// DELETE a conversation
app.delete("/api/conversations/:id", authenticateToken, (req, res) => {
    try {
        const userEmail = req.user.email
        if (!userEmail) {
            return res.status(400).json({
                success: false,
                error: "User email not found in token"
            })
        }
        
        const { id } = req.params
        
        const conversations = getUserConversations(userEmail)
        const filteredConversations = conversations.filter(conv => conv.id !== id)
        
        saveUserConversations(userEmail, filteredConversations)
        
        res.json({
            success: true,
            message: "Conversation deleted",
            deletedId: id
        })
    } catch (error) {
        console.error("Error deleting conversation:", error)
        res.status(500).json({
            success: false,
            error: "Failed to delete conversation",
            details: error.message
        })
    }
})

// POST - Save multiple conversations (for syncing from client)
app.post("/api/conversations/sync", authenticateToken, (req, res) => {
    try {
        const userEmail = req.user.email
        if (!userEmail) {
            return res.status(400).json({
                success: false,
                error: "User email not found in token"
            })
        }
        
        const { conversations } = req.body
        
        if (!Array.isArray(conversations)) {
            return res.status(400).json({
                success: false,
                error: "Invalid data. 'conversations' must be an array."
            })
        }
        
        // Merge with existing conversations (keep server-side ones if client doesn't have them)
        const existingConversations = getUserConversations(userEmail)
        const conversationMap = new Map()
        
        // Add existing conversations to map
        existingConversations.forEach(conv => {
            conversationMap.set(conv.id, conv)
        })
        
        // Update/add with client conversations
        conversations.forEach(conv => {
            if (conv.id && Array.isArray(conv.messages)) {
                conversationMap.set(conv.id, {
                    id: conv.id,
                    title: conv.title || "New Conversation",
                    messages: conv.messages,
                    createdAt: conv.createdAt || Date.now(),
                    updatedAt: conv.updatedAt || Date.now()
                })
            }
        })
        
        // Convert back to array and keep only last 50
        const mergedConversations = Array.from(conversationMap.values()).slice(-50)
        saveUserConversations(userEmail, mergedConversations)
        
        res.json({
            success: true,
            conversations: mergedConversations,
            count: mergedConversations.length,
            message: "Conversations synced successfully"
        })
    } catch (error) {
        console.error("Error syncing conversations:", error)
        res.status(500).json({
            success: false,
            error: "Failed to sync conversations",
            details: error.message
        })
    }
})

// User statistics endpoint
app.get("/api/stats/user/:userId", authenticateToken, (req, res) => {
    try {
        const { userId } = req.params
        const logs = loadConversationLogs().filter(log => log.userId === userId)
        
        if (logs.length === 0) {
            res.json({
                success: true,
                userId,
                stats: {
                    totalConversations: 0,
                    totalMessages: 0,
                    averageResponseTime: 0,
                    toneAdapted: false,
                    toneAdaptationRate: 0,
                    totalTokens: 0,
                    modelsUsed: {},
                },
            })
            return
        }
        
        const totalConversations = logs.length
        const totalMessages = logs.reduce((sum, log) => sum + (log.conversationHistoryLength || 0), 0)
        const responseTimes = logs.map(log => log.timing?.total || 0).filter(t => t > 0)
        const averageResponseTime = responseTimes.length > 0
            ? Math.round(responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length)
            : 0
        
        const toneAdaptedCount = logs.filter(log => log.toneAdapted).length
        const toneAdaptationRate = Math.round((toneAdaptedCount / totalConversations) * 100)
        const toneAdapted = toneAdaptedCount > 0
        
        const totalTokens = logs.reduce((sum, log) => sum + (log.tokens?.total || 0), 0)
        
        const modelsUsed = {}
        logs.forEach(log => {
            modelsUsed[log.model] = (modelsUsed[log.model] || 0) + 1
        })
        
        res.json({
            success: true,
            userId,
            stats: {
                totalConversations,
                totalMessages,
                averageResponseTime,
                toneAdapted,
                toneAdaptationRate,
                totalTokens,
                modelsUsed,
                imageGenerations: logs.filter(log => log.isImageGeneration).length,
                pageScans: logs.filter(log => log.isPageScan).length,
                successRate: Math.round((logs.filter(log => log.model !== "failed" && log.model !== "error").length / totalConversations) * 100),
            },
        })
    } catch (error) {
        console.error("Error fetching user stats:", error)
        res.status(500).json({ error: "Failed to fetch user stats", details: error.message })
    }
})

app.use((err, req, res, next) => {
    // Don't log CORS errors for same-origin requests
    if (err.message === "Not allowed by CORS" && (!req.headers.origin || req.headers.origin.includes('localhost'))) {
        console.error("CORS error (likely same-origin):", err.message)
        return res.status(403).json({ error: "CORS error", message: err.message })
    }
    
    console.error("Server error:", err)
    
    // If it's a request for an HTML page, return HTML error
    if (req.path === '/login' || req.path === '/' || req.path === '/analytics') {
        return res.status(500).send(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Error</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 24px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            text-align: center;
        }
        h1 { color: #ef4444; margin-bottom: 16px; }
        p { color: #64748b; margin-bottom: 24px; }
        a { color: #667eea; text-decoration: none; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <h1>❌ Server Error</h1>
        <p>An unexpected error occurred. Please try again.</p>
        <a href="/login">← Back to Login</a>
    </div>
</body>
</html>
        `)
    }
    
    res.status(500).json({ error: "Unexpected server error", message: err.message })
})

// Demo Keys Storage File
const DEMO_KEYS_FILE = join(__dirname, "demo_keys.json")

function loadDemoKeys() {
    if (existsSync(DEMO_KEYS_FILE)) {
        try {
            const data = readFileSync(DEMO_KEYS_FILE, "utf-8")
            return JSON.parse(data)
        } catch (error) {
            log(`[Demo Keys] Error loading demo keys: ${error.message}`, "error")
            return { keys: [] }
        }
    }
    return { keys: [] }
}

function saveDemoKeys(data) {
    try {
        writeFileSync(DEMO_KEYS_FILE, JSON.stringify(data, null, 2), "utf-8")
        return true
    } catch (error) {
        log(`[Demo Keys] Error saving demo keys: ${error.message}`, "error")
        return false
    }
}

// Contact form endpoint
app.post("/api/contact", apiLimiter, async (req, res) => {
    try {
        const { email, message } = req.body

        if (!email || !message) {
            return res.status(400).json({
                success: false,
                error: "Email and message are required"
            })
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                error: "Invalid email format"
            })
        }

        // Save contact message to file
        const CONTACTS_FILE = join(__dirname, "contacts.json")
        let contacts = []
        
        if (existsSync(CONTACTS_FILE)) {
            try {
                const data = readFileSync(CONTACTS_FILE, "utf-8")
                contacts = JSON.parse(data)
            } catch (error) {
                log(`[Contact] Error loading contacts: ${error.message}`, "error")
            }
        }

        const contactEntry = {
            id: `contact_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            email,
            message,
            timestamp: new Date().toISOString(),
            read: false
        }

        contacts.push(contactEntry)
        writeFileSync(CONTACTS_FILE, JSON.stringify(contacts, null, 2), "utf-8")

        log(`[Contact] New contact form submission from: ${email}`)

        // Send email notification (non-blocking)
        sendContactEmailNotification(email, message).catch(err => {
            log(`[Contact] Email notification failed: ${err.message}`, "error")
        })

        res.json({
            success: true,
            message: "Thank you for your message! We'll get back to you soon."
        })
    } catch (error) {
        log(`[Contact] Error processing contact form: ${error.message}`, "error")
        res.status(500).json({
            success: false,
            error: "Failed to send message. Please try again."
        })
    }
})

// Newsletter subscription endpoint
app.post("/api/newsletter/subscribe", apiLimiter, async (req, res) => {
    try {
        const { email } = req.body

        if (!email) {
            return res.status(400).json({
                success: false,
                error: "Email is required"
            })
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                error: "Invalid email format"
            })
        }

        // Save newsletter subscription to file
        const NEWSLETTER_FILE = join(__dirname, "newsletter_subscribers.json")
        let subscribers = []
        
        if (existsSync(NEWSLETTER_FILE)) {
            try {
                const data = readFileSync(NEWSLETTER_FILE, "utf-8")
                subscribers = JSON.parse(data)
            } catch (error) {
                log(`[Newsletter] Error loading subscribers: ${error.message}`, "error")
            }
        }

        // Check if email already exists
                const existingSubscriber = subscribers.find((sub) => sub.email.toLowerCase() === email.toLowerCase())
        if (existingSubscriber) {
            return res.json({
                success: true,
                message: "You're already subscribed! Thank you for your interest.",
                alreadySubscribed: true
            })
        }

        const subscriberEntry = {
            id: `sub_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            email: email.toLowerCase(),
            subscribedAt: new Date().toISOString(),
            active: true
        }

        subscribers.push(subscriberEntry)
        writeFileSync(NEWSLETTER_FILE, JSON.stringify(subscribers, null, 2), "utf-8")

        log(`[Newsletter] New subscription from: ${email}`)

        // Send email notification (non-blocking)
        sendNewsletterSubscriptionNotification(email).catch(err => {
            log(`[Newsletter] Email notification failed: ${err.message}`, "error")
        })

        res.json({
            success: true,
            message: "Thank you for subscribing! You'll receive updates soon."
        })
    } catch (error) {
        log(`[Newsletter] Error processing subscription: ${error.message}`, "error")
        res.status(500).json({
            success: false,
            error: "Failed to subscribe. Please try again."
        })
    }
})

// Email notification for newsletter subscriptions
async function sendNewsletterSubscriptionNotification(email) {
    try {
        const resendApiKey = process.env.RESEND_API_KEY
        const fromEmail = process.env.RESEND_FROM_EMAIL || 'onboarding@resend.dev'
        const toEmail = process.env.RESEND_TO_EMAIL || 'darshvekaria1@gmail.com'

        if (!resendApiKey) {
            log(`[Newsletter Email] RESEND_API_KEY not configured. Subscription saved to file only.`)
            return { messageId: 'logged-only', error: 'Resend API key not configured' }
        }

        const resend = new Resend(resendApiKey)

        const emailPromise = resend.emails.send({
            from: `Lumra AI <${fromEmail}>`,
            to: [toEmail],
            subject: `📬 New Newsletter Subscription - ${email}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #333; border-bottom: 2px solid #6366f1; padding-bottom: 10px;">New Newsletter Subscription</h2>
                    <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <p style="margin: 10px 0;"><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
                        <p style="margin: 10px 0;"><strong>Subscribed At:</strong> ${new Date().toLocaleString()}</p>
                        <p style="margin: 10px 0;"><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
                    </div>
                    <p style="color: #999; font-size: 12px; margin-top: 30px;">This is an automated notification from Lumra AI newsletter subscription.</p>
                </div>
            `,
            text: `
New Newsletter Subscription

Email: ${email}
Subscribed At: ${new Date().toLocaleString()}
Timestamp: ${new Date().toISOString()}
            `
        })

        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Resend API timeout')), 10000)
        )

        const info = await Promise.race([emailPromise, timeoutPromise])
        log(`[Newsletter Email] ✅ Email sent successfully via Resend! Message ID: ${info.data?.id || 'unknown'}`)
        return info
    } catch (error) {
        log(`[Newsletter Email] ❌ Error sending email: ${error.message}`, "error")
        return { messageId: 'failed', error: error.message }
    }
}

// Demo key validation endpoint
// Demo key request endpoint
app.post("/api/demo/request", apiLimiter, async (req, res) => {
    try {
        const { name, email } = req.body

        if (!name || !email || typeof name !== "string" || typeof email !== "string") {
            return res.status(400).json({
                success: false,
                message: "Name and email are required"
            })
        }

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        if (!emailRegex.test(email.trim())) {
            return res.status(400).json({
                success: false,
                message: "Invalid email address"
            })
        }

        const trimmedName = name.trim()
        const trimmedEmail = email.trim()

        // Save demo key request to file (similar to contact form)
        const DEMO_REQUESTS_FILE = join(__dirname, "demo_requests.json")
        let requests = []
        
        if (existsSync(DEMO_REQUESTS_FILE)) {
            try {
                const data = readFileSync(DEMO_REQUESTS_FILE, "utf-8")
                requests = JSON.parse(data)
            } catch (error) {
                log(`[Demo Key Request] Error loading requests: ${error.message}`, "error")
            }
        }

        const requestEntry = {
            id: `demo_request_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            name: trimmedName,
            email: trimmedEmail,
            timestamp: new Date().toISOString(),
            status: "pending",
            keyGenerated: false
        }

        requests.push(requestEntry)
        writeFileSync(DEMO_REQUESTS_FILE, JSON.stringify(requests, null, 2), "utf-8")

        log(`[Demo Key Request] New request from: ${trimmedName} (${trimmedEmail})`)

        // Send email notification asynchronously (don't wait for it)
        // Also log to a simple text file for easy access
        const simpleLogFile = join(__dirname, "demo_requests_simple.txt")
        const simpleLogEntry = `${new Date().toISOString()} | ${trimmedName} | ${trimmedEmail}\n`
        try {
            appendFileSync(simpleLogFile, simpleLogEntry, "utf-8")
            log(`[Demo Key Request] ✅ Request saved to demo_requests_simple.txt`)
        } catch (logErr) {
            log(`[Demo Key Request] Error writing simple log: ${logErr.message}`)
        }

        sendDemoKeyRequestEmail(trimmedName, trimmedEmail).catch((emailError) => {
            log(`[Demo Key Request] ⚠️ Email sending failed (but request is saved): ${emailError.message}`, "error")
        })

        // Return success immediately (don't wait for email)
        return res.json({
            success: true,
            message: "Demo key request submitted successfully. We'll send you a key soon!"
        })
    } catch (error) {
        log(`[Demo Key Request] Error processing request: ${error.message}`, "error")
        res.status(500).json({
            success: false,
            message: "Error processing request. Please try again."
        })
    }
})

// Get demo key requests (for admin/developer to view)
app.get("/api/demo/requests", requireDeveloperAuth, async (req, res) => {
    try {
        const DEMO_REQUESTS_FILE = join(__dirname, "demo_requests.json")
        
        if (!existsSync(DEMO_REQUESTS_FILE)) {
            return res.json({ requests: [] })
        }

        const data = readFileSync(DEMO_REQUESTS_FILE, "utf-8")
        const requests = JSON.parse(data)
        
        // Sort by timestamp (newest first)
        requests.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))

        res.json({ requests })
    } catch (error) {
        log(`[Demo Requests] Error loading requests: ${error.message}`, "error")
        res.status(500).json({ error: "Error loading requests" })
    }
})

// Handle OPTIONS preflight for demo validate endpoint
app.options("/api/demo/validate", (req, res) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*')
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS')
    res.header('Access-Control-Allow-Headers', 'Content-Type')
    res.header('Access-Control-Allow-Credentials', 'true')
    res.sendStatus(200)
})

app.post("/api/demo/validate", apiLimiter, async (req, res) => {
    try {
        log(`[Demo Key] Validation request received`)
        log(`[Demo Key] Request method: ${req.method}`)
        log(`[Demo Key] Request headers: ${JSON.stringify(req.headers)}`)
        log(`[Demo Key] Request body: ${JSON.stringify(req.body)}`)
        
        // First check if demo keys are revoked (with error handling)
        let revocationStatus
        try {
            revocationStatus = loadDemoKeyRevocation()
            log(`[Demo Key] Revocation status loaded: ${JSON.stringify(revocationStatus)}`)
        } catch (revError) {
            log(`[Demo Key] Error loading revocation status: ${revError.message}`, "error")
            log(`[Demo Key] Revocation error stack: ${revError.stack}`, "error")
            // Default to not revoked if we can't load the status
            revocationStatus = { revoked: false, revokedAt: null, revokedBy: null }
        }

        if (revocationStatus && revocationStatus.revoked === true) {
            log(`[Demo Key] Validation rejected - demo keys are revoked`)
            return res.json({
                valid: false,
                revoked: true,
                message: "Demo keys have been revoked. Please contact support for access."
            })
        }

        // Extract key from request body (handle different formats)
        let key = req.body?.key || req.body?.demoKey || req.body?.keyValue
        
        // If key is not in body, check query params as fallback
        if (!key) {
            key = req.query?.key || req.query?.demoKey
        }

        if (!key) {
            log(`[Demo Key] No key provided in request`)
            // Set CORS headers
            if (req.headers.origin) {
                res.header('Access-Control-Allow-Origin', req.headers.origin)
                res.header('Access-Control-Allow-Credentials', 'true')
            }
            return res.status(400).json({
                valid: false,
                message: "Demo key is required"
            })
        }

        // Normalize the key: convert to string, trim whitespace
        const trimmedKey = String(key).trim()
        const expectedKey = "12121"
        
        log(`[Demo Key] Raw key received: ${JSON.stringify(key)}`)
        log(`[Demo Key] Key type: ${typeof key}`)
        log(`[Demo Key] Trimmed key: "${trimmedKey}" (length: ${trimmedKey.length})`)
        log(`[Demo Key] Expected key: "${expectedKey}" (length: ${expectedKey.length})`)
        
        // Simple, direct comparison
        if (trimmedKey === expectedKey) {
            log(`[Demo Key] ✅ Valid key accepted: 12121`)

            // Set CORS headers
            res.header('Access-Control-Allow-Origin', req.headers.origin || '*')
            res.header('Access-Control-Allow-Credentials', 'true')
            
            return res.json({
                valid: true,
                message: "Demo key is valid"
            })
        }

        log(`[Demo Key] ❌ Invalid key rejected: "${trimmedKey}" (expected: "${expectedKey}")`)

        // Set CORS headers
        res.header('Access-Control-Allow-Origin', req.headers.origin || '*')
        res.header('Access-Control-Allow-Credentials', 'true')
        
        res.json({
            valid: false,
            message: "Invalid demo key. Please check and try again."
        })
    } catch (error) {
        log(`[Demo Key] ⚠️ Error validating demo key: ${error.message}`, "error")
        log(`[Demo Key] Error stack: ${error.stack}`, "error")
        res.status(500).json({
            valid: false,
            message: "Error validating key. Please try again.",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        })
    }
})

// Test endpoint removed for security - do not expose demo key

// Calendar API endpoints
app.get("/api/calendar", authenticateToken, (req, res) => {
    try {
        const userEmail = req.user?.email
        if (!userEmail) {
            return res.status(400).json({
                success: false,
                error: "User email not found"
            })
        }
        
        const calendarData = getUserCalendar(userEmail)
        res.json({
            success: true,
            calendar: calendarData
        })
    } catch (error) {
        log(`[Calendar] Error getting calendar: ${error.message}`, "error")
        res.status(500).json({
            success: false,
            error: "Failed to get calendar data"
        })
    }
})

app.post("/api/calendar", authenticateToken, (req, res) => {
    try {
        const userEmail = req.user?.email
        if (!userEmail) {
            return res.status(400).json({
                success: false,
                error: "User email not found"
            })
        }
        
        const { events, dueDates, classes } = req.body
        
        const calendarData = {
            events: events || [],
            dueDates: dueDates || [],
            classes: classes || [],
            updatedAt: new Date().toISOString()
        }
        
        saveUserCalendar(userEmail, calendarData)
        
        log(`[Calendar] Saved calendar data for user: ${userEmail}`)
        
        res.json({
            success: true,
            message: "Calendar data saved successfully"
        })
    } catch (error) {
        log(`[Calendar] Error saving calendar: ${error.message}`, "error")
        res.status(500).json({
            success: false,
            error: "Failed to save calendar data"
        })
    }
})

// Generate demo key endpoint (for admin/developer)
app.post("/api/demo/generate", requireDeveloperAuth, async (req, res) => {
    try {
        const { name, email, expiresInDays } = req.body

        // Generate a secure demo key
        const generateKey = () => {
            const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Removed confusing chars
            let key = "DEMO-"
            for (let i = 0; i < 12; i++) {
                key += chars.charAt(Math.floor(Math.random() * chars.length))
            }
            return key
        }

        const newKey = generateKey()
        const expiresAt = expiresInDays 
            ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString()
            : null

        const demoKeysData = loadDemoKeys()
        
        const keyEntry = {
            key: newKey,
            name: name || "Unnamed",
            email: email || null,
            createdAt: new Date().toISOString(),
            expiresAt,
            active: true,
            usageCount: 0,
            lastUsed: null
        }

        demoKeysData.keys.push(keyEntry)
        saveDemoKeys(demoKeysData)

        log(`[Demo Key] New demo key generated: ${newKey.substring(0, 8)}...`)

        res.json({
            success: true,
            key: newKey,
            expiresAt,
            message: "Demo key generated successfully"
        })
    } catch (error) {
        log(`[Demo Key] Error generating demo key: ${error.message}`, "error")
        res.status(500).json({
            success: false,
            error: "Failed to generate demo key"
        })
    }
})

// Get all demo keys (for admin)
app.get("/api/demo/keys", requireDeveloperAuth, async (req, res) => {
    try {
        const demoKeysData = loadDemoKeys()
        res.json({
            success: true,
            keys: demoKeysData.keys.map(k => ({
                key: k.key,
                name: k.name,
                email: k.email,
                createdAt: k.createdAt,
                expiresAt: k.expiresAt,
                active: k.active,
                usageCount: k.usageCount,
                lastUsed: k.lastUsed
            }))
        })
    } catch (error) {
        log(`[Demo Key] Error fetching demo keys: ${error.message}`, "error")
        res.status(500).json({
            success: false,
            error: "Failed to fetch demo keys"
        })
    }
})

// Demo key revocation status file
const DEMO_KEY_REVOCATION_FILE = join(__dirname, "demo_key_revocation.json")

function loadDemoKeyRevocation() {
    if (existsSync(DEMO_KEY_REVOCATION_FILE)) {
        try {
            const data = readFileSync(DEMO_KEY_REVOCATION_FILE, "utf-8")
            return JSON.parse(data)
        } catch (error) {
            log(`[Demo Key Revocation] Error loading revocation status: ${error.message}`, "error")
            return { revoked: false, revokedAt: null, revokedBy: null }
        }
    }
    return { revoked: false, revokedAt: null, revokedBy: null }
}

function saveDemoKeyRevocation(data) {
    try {
        // Ensure revoked is explicitly a boolean
        const dataToSave = {
            ...data,
            revoked: Boolean(data.revoked)
        }
        writeFileSync(DEMO_KEY_REVOCATION_FILE, JSON.stringify(dataToSave, null, 2), "utf-8")
        log(`[Demo Key Revocation] ✅ Saved revocation status: revoked=${dataToSave.revoked}, file: ${DEMO_KEY_REVOCATION_FILE}`)
        return true
    } catch (error) {
        log(`[Demo Key Revocation] Error saving revocation status: ${error.message}`, "error")
        log(`[Demo Key Revocation] Error stack: ${error.stack}`, "error")
        return false
    }
}

// Check if demo keys are currently valid (public endpoint)
app.get("/api/demo/status", async (req, res) => {
    try {
        // Add CORS headers to allow frontend access
        res.setHeader('Access-Control-Allow-Origin', '*')
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private')
        res.setHeader('Pragma', 'no-cache')
        res.setHeader('Expires', '0')
        
        // Load revocation status fresh from file
        const revocationStatus = loadDemoKeyRevocation()
        
        // Ensure we're reading the boolean correctly (handle string "true"/"false" or boolean)
        const isRevoked = revocationStatus.revoked === true || revocationStatus.revoked === "true" || revocationStatus.revoked === 1
        
        const status = {
            valid: !isRevoked,
            revoked: isRevoked,
            revokedAt: revocationStatus.revokedAt,
            revokedBy: revocationStatus.revokedBy,
            message: isRevoked 
                ? "Demo keys have been revoked. Please contact support for access." 
                : "Demo keys are currently valid"
        }
        
        log(`[Demo Key Status] Status check: revoked=${status.revoked} (raw: ${revocationStatus.revoked}), valid=${status.valid}, file exists: ${existsSync(DEMO_KEY_REVOCATION_FILE)}`)
        res.json(status)
    } catch (error) {
        log(`[Demo Key Status] Error checking status: ${error.message}`, "error")
        res.status(500).json({
            valid: false,
            revoked: true, // Fail closed - assume revoked on error
            error: "Failed to check demo key status"
        })
    }
})

// Revoke all demo keys (admin endpoint)
app.post("/api/demo/revoke-all", requireDeveloperAuth, async (req, res) => {
    try {
        const revocationData = {
            revoked: true, // Explicitly set to boolean true
            revokedAt: new Date().toISOString(),
            revokedBy: req.session?.developerUsername || req.session?.developerEmail || "admin",
            message: req.body.message || "All demo keys have been revoked by administrator"
        }
        
        log(`[Demo Key Revocation] Attempting to revoke demo keys...`)
        log(`[Demo Key Revocation] Data to save:`, JSON.stringify(revocationData))
        
        const saved = saveDemoKeyRevocation(revocationData)
        if (!saved) {
            log(`[Demo Key Revocation] ⚠️ Warning: Failed to save revocation data`, "error")
            return res.status(500).json({
                success: false,
                error: "Failed to save revocation status"
            })
        }
        
        // Small delay to ensure file is written
        await new Promise(resolve => setTimeout(resolve, 100))
        
        // Verify the revocation was saved by reading the file directly
        const verifyStatus = loadDemoKeyRevocation()
        const isActuallyRevoked = verifyStatus.revoked === true || verifyStatus.revoked === "true"
        
        log(`[Demo Key Revocation] ✅ All demo keys revoked by ${revocationData.revokedBy}`)
        log(`[Demo Key Revocation] Verification: revoked=${isActuallyRevoked} (raw: ${verifyStatus.revoked}), revokedAt=${verifyStatus.revokedAt}`)
        log(`[Demo Key Revocation] File path: ${DEMO_KEY_REVOCATION_FILE}`)
        log(`[Demo Key Revocation] File exists: ${existsSync(DEMO_KEY_REVOCATION_FILE)}`)
        
        if (!isActuallyRevoked) {
            log(`[Demo Key Revocation] ⚠️ WARNING: Revocation status not properly saved!`, "error")
        }
        
        res.json({
            success: true,
            message: "All demo keys have been revoked. All demo key users will be logged out within 5 seconds.",
            revokedAt: revocationData.revokedAt,
            verified: isActuallyRevoked,
            filePath: DEMO_KEY_REVOCATION_FILE
        })
    } catch (error) {
        log(`[Demo Key Revocation] Error revoking demo keys: ${error.message}`, "error")
        log(`[Demo Key Revocation] Error stack: ${error.stack}`, "error")
        res.status(500).json({
            success: false,
            error: "Failed to revoke demo keys: " + error.message
        })
    }
})

// Restore demo keys (admin endpoint)
app.post("/api/demo/restore", requireDeveloperAuth, async (req, res) => {
    try {
        const revocationData = {
            revoked: false,
            revokedAt: null,
            revokedBy: null,
            restoredAt: new Date().toISOString(),
            restoredBy: req.session?.developerUsername || req.session?.developerEmail || "admin"
        }
        
        saveDemoKeyRevocation(revocationData)
        log(`[Demo Key Revocation] ✅ Demo keys restored by ${revocationData.restoredBy}`)
        
        res.json({
            success: true,
            message: "Demo keys have been restored. Users can now access the demo again.",
            restoredAt: revocationData.restoredAt
        })
    } catch (error) {
        log(`[Demo Key Revocation] Error restoring demo keys: ${error.message}`, "error")
        res.status(500).json({
            success: false,
            error: "Failed to restore demo keys"
        })
    }
})

// Demo Key Management Page (admin interface)
app.get("/demo-keys", requireDeveloperAuth, async (req, res) => {
    try {
        const revocationStatus = loadDemoKeyRevocation()
        const demoKeysData = loadDemoKeys()
        
        res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo Key Management - Lumra Backend</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
            min-height: 100vh;
            padding: 20px;
            color: #e2e8f0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            border: 2px solid #6366f1;
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        .header h1 {
            color: #fbbf24;
            font-size: 2rem;
            margin-bottom: 10px;
        }
        .header p {
            color: #94a3b8;
        }
        .status-card {
            background: #1e293b;
            border: 2px solid ${revocationStatus.revoked ? '#ef4444' : '#10b981'};
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.3);
        }
        .status-card h2 {
            color: ${revocationStatus.revoked ? '#fca5a5' : '#6ee7b7'};
            margin-bottom: 15px;
            font-size: 1.5rem;
        }
        .status-info {
            color: #cbd5e1;
            margin-bottom: 10px;
        }
        .status-info strong {
            color: #fbbf24;
        }
        .actions {
            display: flex;
            gap: 15px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-block;
        }
        .btn-revoke {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
        }
        .btn-revoke:hover {
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(239, 68, 68, 0.5);
        }
        .btn-restore {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
        }
        .btn-restore:hover {
            background: linear-gradient(135deg, #059669 0%, #047857 100%);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(16, 185, 129, 0.5);
        }
        .btn-check {
            background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
            color: white;
        }
        .btn-check:hover {
            background: linear-gradient(135deg, #4f46e5 0%, #4338ca 100%);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(99, 102, 241, 0.5);
        }
        .btn-back {
            background: #334155;
            color: white;
        }
        .btn-back:hover {
            background: #475569;
        }
        .message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        .message.success {
            background: rgba(16, 185, 129, 0.2);
            border: 1px solid #10b981;
            color: #6ee7b7;
        }
        .message.error {
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid #ef4444;
            color: #fca5a5;
        }
        .warning-box {
            background: rgba(239, 68, 68, 0.1);
            border: 2px solid #ef4444;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .warning-box h3 {
            color: #fca5a5;
            margin-bottom: 10px;
        }
        .warning-box p {
            color: #fca5a5;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔑 Demo Key Management</h1>
            <p>Manage demo key access and revocation on api.lumraedu.com</p>
            <p style="margin-top: 10px; font-size: 0.9rem; color: #64748b;">
                <strong>Domain:</strong> api.lumraedu.com | 
                <strong>Status Endpoint:</strong> <a href="/api/demo/status" style="color: #6366f1; text-decoration: none;">/api/demo/status</a>
            </p>
        </div>

        <div id="message" class="message"></div>

        <div class="status-card">
            <h2>${revocationStatus.revoked ? '❌ Demo Keys REVOKED' : '✅ Demo Keys ACTIVE'}</h2>
            ${revocationStatus.revoked ? `
                <div class="status-info">
                    <strong>Revoked At:</strong> ${revocationStatus.revokedAt ? new Date(revocationStatus.revokedAt).toLocaleString() : 'N/A'}<br>
                    <strong>Revoked By:</strong> ${revocationStatus.revokedBy || 'N/A'}<br>
                    <strong>Domain:</strong> api.lumraedu.com
                </div>
                <div class="warning-box">
                    <h3>⚠️ Warning</h3>
                    <p>All demo keys are currently revoked. Users with demo keys will be automatically logged out and redirected to the landing page.</p>
                    <p style="margin-top: 10px;"><strong>What happens:</strong> When you revoke demo keys, all users currently using demo keys (stored in localStorage) will be kicked out within 30 seconds. The frontend checks the status every 30 seconds and automatically redirects revoked users.</p>
                </div>
            ` : `
                <div class="status-info">
                    <strong>Status:</strong> Demo keys are currently active and valid.<br>
                    <strong>Domain:</strong> api.lumraedu.com<br>
                    Users can use demo keys to access the application.
                </div>
            `}
            
            <div class="actions">
                ${revocationStatus.revoked ? `
                    <button class="btn btn-restore" onclick="restoreDemoKeys()">✅ Restore Demo Keys</button>
                ` : `
                    <button class="btn btn-revoke" onclick="revokeDemoKeys()">❌ Revoke All Demo Keys</button>
                `}
                <button class="btn btn-check" onclick="checkStatus()">🔄 Check Status</button>
                <a href="/" class="btn btn-back">← Back to Dashboard</a>
            </div>
        </div>
    </div>

    <script>
        function showMessage(text, type) {
            const msgEl = document.getElementById('message');
            msgEl.textContent = text;
            msgEl.className = 'message ' + type;
            msgEl.style.display = 'block';
            setTimeout(() => {
                msgEl.style.display = 'none';
            }, 5000);
        }

        async function revokeDemoKeys() {
            if (!confirm('⚠️ WARNING: This will revoke ALL demo keys and kick out ALL users currently using demo keys. Are you sure?')) {
                return;
            }
            
            try {
                const response = await fetch('/api/demo/revoke-all', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include'
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showMessage('✅ ' + data.message + ' All users will be kicked out within 10 seconds.', 'success');
                    // Reload after showing message
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showMessage('❌ Error: ' + (data.error || 'Failed to revoke demo keys'), 'error');
                }
            } catch (error) {
                showMessage('❌ Error: ' + error.message, 'error');
                console.error('Revoke error:', error);
            }
        }

        async function restoreDemoKeys() {
            if (!confirm('✅ Restore demo keys? This will allow users to use demo keys again.')) {
                return;
            }
            
            try {
                const response = await fetch('/api/demo/restore', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showMessage('✅ ' + data.message, 'success');
                    setTimeout(() => location.reload(), 1500);
                } else {
                    showMessage('❌ Error: ' + (data.error || 'Failed to restore demo keys'), 'error');
                }
            } catch (error) {
                showMessage('❌ Error: ' + error.message, 'error');
            }
        }

        async function checkStatus() {
            try {
                const response = await fetch('/api/demo/status');
                const data = await response.json();
                
                if (data.revoked) {
                    showMessage('❌ Demo keys are REVOKED. Revoked at: ' + (data.revokedAt ? new Date(data.revokedAt).toLocaleString() : 'N/A'), 'error');
                } else {
                    showMessage('✅ Demo keys are ACTIVE and valid', 'success');
                }
            } catch (error) {
                showMessage('❌ Error checking status: ' + error.message, 'error');
            }
        }
    </script>
</body>
</html>
        `)
    } catch (error) {
        log(`[Demo Key Management] Error loading page: ${error.message}`, "error")
        res.status(500).send("Error loading demo key management page")
    }
})

app.listen(port, () => {
    const startupMessage = `
╔═══════════════════════════════════════════════════════════╗
║           🚀 Lumra Backend Server Started                 ║
╚═══════════════════════════════════════════════════════════╝
📡 Server: http://localhost:${port}
📊 Health: http://localhost:${port}/health
🌐 Status: http://localhost:${port}/
📝 Logs: ${LOG_FILE}
═══════════════════════════════════════════════════════════
`
    console.log(startupMessage)
    log(`🚀 Lumra API listening on http://localhost:${port}`)
    log(`📡 Health check: http://localhost:${port}/health`)
    log(`🌐 Status page: http://localhost:${port}/`)
    log(`📝 All logs are being saved to: ${LOG_FILE}`)
    
    // OAuth status
    if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
        const callbackUrl = process.env.GOOGLE_CALLBACK_URL || `http://localhost:${port}/api/auth/google/callback`
        console.log(`✅ Google OAuth: Configured and ready`)
        console.log(`   Client ID: ${GOOGLE_CLIENT_ID.substring(0, 20)}...`)
        console.log(`   Callback URL: ${callbackUrl}`)
        console.log(`   Login: http://localhost:${port}/api/auth/google`)
        if (!process.env.GOOGLE_CALLBACK_URL) {
            console.log(`   ⚠️  Using default callback URL (localhost). For production, set GOOGLE_CALLBACK_URL`)
        }
    } else {
        console.log(`⚠️  Google OAuth: Not configured`)
        if (!GOOGLE_CLIENT_ID) {
            console.log(`   ❌ GOOGLE_CLIENT_ID is missing in .env file`)
        }
        if (!GOOGLE_CLIENT_SECRET) {
            console.log(`   ❌ GOOGLE_CLIENT_SECRET is missing in .env file`)
        }
        console.log(`   Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to enable Google login`)
    }
    
    // API status
    if (openaiClient && anthropicClient) {
        console.log(`✅ Both AI services: Ready`)
    } else {
        if (!openaiClient) console.log(`❌ OpenAI: Not configured`)
        if (!anthropicClient) console.log(`❌ Anthropic: Not configured`)
    }
})


