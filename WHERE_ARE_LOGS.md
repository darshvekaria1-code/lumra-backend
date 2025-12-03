# Where to Find Backend Logs

## 📍 Log Locations

### 1. **Console/Terminal** (Real-time)
When you run the server, logs appear in the terminal/console where you started it.

**To see logs:**
- Open your terminal/PowerShell
- Navigate to the `lumra` folder
- Run: `npm start` or `node server.js`
- **All logs will appear in real-time in the terminal**

### 2. **Log File** (Permanent Record)
All logs are also saved to a file for later viewing.

**Location:** `lumra/server.log`

**To view logs:**
```bash
# Windows PowerShell
Get-Content lumra/server.log -Tail 50

# Or open in notepad
notepad lumra/server.log

# Or use any text editor
code lumra/server.log
```

---

## 🔍 What Logs You'll See

### When Server Starts:
```
╔═══════════════════════════════════════════════════════════╗
║           🚀 Lumra Backend Server Started                 ║
╚═══════════════════════════════════════════════════════════╝
📡 Server: http://localhost:5050
📊 Health: http://localhost:5050/health
🌐 Status: http://localhost:5050/
📝 Logs: C:\Users\forty\...\lumra\server.log
```

### When Using Refined Mode:
```
[2025-01-15T10:30:00.000Z] [API Request] Received mode parameter: "refined"
[2025-01-15T10:30:00.100Z] [Refined Mode] ===== STARTING REFINED MODE =====
[2025-01-15T10:30:00.101Z] [Refined Mode] Mode parameter received: "refined"
[2025-01-15T10:30:00.102Z] [Refined Mode] Step 1: ChatGPT generating initial response...
[2025-01-15T10:30:02.500Z] [Refined Mode] Step 1 Complete: ChatGPT generated 500 chars (250 tokens, 2400ms)
[2025-01-15T10:30:02.501Z] [Refined Mode] Step 2: Claude refining ChatGPT's response...
[2025-01-15T10:30:02.502Z] [Refined Mode] Calling Claude API...
[2025-01-15T10:30:02.503Z] [Refined Mode] Claude model: claude-3-5-sonnet-20240620
[2025-01-15T10:30:02.504Z] [Refined Mode] Anthropic client available: YES
[2025-01-15T10:30:04.800Z] [Refined Mode] Claude API call completed successfully!
[2025-01-15T10:30:04.801Z] [Refined Mode] Step 2 Complete: Claude refined to 600 chars (300 tokens, 2300ms)
[2025-01-15T10:30:04.802Z] [Refined Mode] Total: 600 chars, 550 tokens, 4800ms
[2025-01-15T10:30:04.803Z] [Refined Mode] Timing: ChatGPT: 2400ms | Claude: 2300ms | Total: 4800ms
[2025-01-15T10:30:04.804Z] [Refined Mode] ===== REFINED MODE COMPLETED SUCCESSFULLY =====
```

### When Using Quick Mode:
```
[2025-01-15T10:30:00.000Z] [AI Integration] Mode: QUICK (Parallel)
[2025-01-15T10:30:00.100Z] [Quick Mode] Calling both AIs in parallel...
[2025-01-15T10:30:02.500Z] [ChatGPT Response] (500 chars, 250 tokens, 2400ms)
[2025-01-15T10:30:02.600Z] [Claude Response] ✅ SUCCESS (600 chars, 300 tokens, 2500ms)
```

---

## 🛠️ How to View Logs

### Option 1: Watch Terminal (Real-time)
1. Start the server: `npm start`
2. Keep the terminal open
3. All logs appear in real-time as requests come in

### Option 2: View Log File
1. Open `lumra/server.log` in any text editor
2. Or use PowerShell: `Get-Content lumra/server.log -Tail 100`
3. Or use: `Get-Content lumra/server.log -Wait` (live updates)

### Option 3: Filter Logs
```powershell
# See only Refined Mode logs
Select-String -Path lumra/server.log -Pattern "Refined Mode"

# See only errors
Select-String -Path lumra/server.log -Pattern "ERROR"

# See last 50 lines
Get-Content lumra/server.log -Tail 50
```

---

## ✅ What to Look For

### If Refined Mode is Working:
✅ You'll see: `[Refined Mode] ===== STARTING REFINED MODE =====`  
✅ You'll see: `[Refined Mode] Step 1: ChatGPT generating...`  
✅ You'll see: `[Refined Mode] Step 2: Claude refining...`  
✅ You'll see: `[Refined Mode] Claude API call completed successfully!`  
✅ You'll see: `[Refined Mode] ===== REFINED MODE COMPLETED SUCCESSFULLY =====`

### If Refined Mode is NOT Working:
❌ You'll see: `[AI Integration] Mode: QUICK (Parallel)` (wrong mode)  
❌ You'll see: `[Refined Mode] ERROR in refined mode pipeline`  
❌ You'll see: `Anthropic client available: NO` (Claude not configured)

---

## 📝 Log File Details

- **Location**: `lumra/server.log`
- **Format**: Each line has timestamp + message
- **Size**: Grows over time (you can delete it to start fresh)
- **Backup**: Logs are saved automatically, no action needed

---

## 🔧 Troubleshooting

### "I don't see any logs"
1. Make sure the server is running
2. Check the terminal where you started the server
3. Check if `lumra/server.log` file exists

### "Logs are too long"
```powershell
# View only last 100 lines
Get-Content lumra/server.log -Tail 100

# Or clear the log file (starts fresh)
Clear-Content lumra/server.log
```

### "I want to see only Refined Mode logs"
```powershell
Select-String -Path lumra/server.log -Pattern "Refined Mode"
```

---

**All logs are now saved to both console AND file!** 📝


