#!/usr/bin/env node

/**
 * Simple script to generate a demo key
 * Usage: node generate-demo-key.js [name] [email] [days]
 * Example: node generate-demo-key.js "John Doe" "john@example.com" 30
 */

import { readFileSync, writeFileSync, existsSync } from "fs"
import { join, dirname } from "path"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const DEMO_KEYS_FILE = join(__dirname, "demo_keys.json")

function loadDemoKeys() {
    if (existsSync(DEMO_KEYS_FILE)) {
        try {
            const data = readFileSync(DEMO_KEYS_FILE, "utf-8")
            return JSON.parse(data)
        } catch (error) {
            console.error("Error loading demo keys:", error.message)
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
        console.error("Error saving demo keys:", error.message)
        return false
    }
}

function generateKey() {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    let key = "DEMO-"
    for (let i = 0; i < 12; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length))
    }
    return key
}

// Get command line arguments
const name = process.argv[2] || "Demo User"
const email = process.argv[3] || null
const expiresInDays = process.argv[4] ? parseInt(process.argv[4]) : null

// Generate key
const newKey = generateKey()
const expiresAt = expiresInDays 
    ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString()
    : null

const demoKeysData = loadDemoKeys()

const keyEntry = {
    key: newKey,
    name,
    email,
    createdAt: new Date().toISOString(),
    expiresAt,
    active: true,
    usageCount: 0,
    lastUsed: null
}

demoKeysData.keys.push(keyEntry)
saveDemoKeys(demoKeysData)

console.log("\n✅ Demo key generated successfully!\n")
console.log("Key:", newKey)
console.log("Name:", name)
if (email) console.log("Email:", email)
if (expiresAt) console.log("Expires:", expiresAt)
console.log("\nShare this key with users to grant them access to the platform.\n")





