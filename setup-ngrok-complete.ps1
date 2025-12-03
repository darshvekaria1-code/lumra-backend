# Complete ngrok Setup Script
# This will help you set up ngrok step by step

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ngrok Complete Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Find ngrok
Write-Host "[1/4] Finding ngrok..." -ForegroundColor Yellow

$ngrokPath = $null

# Check common locations
$possiblePaths = @(
    "C:\ngrok\ngrok.exe",
    "$env:USERPROFILE\Downloads\ngrok.exe",
    "$env:USERPROFILE\Desktop\ngrok.exe",
    "$env:ProgramFiles\ngrok\ngrok.exe",
    "$env:LOCALAPPDATA\ngrok\ngrok.exe"
)

foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $ngrokPath = $path
        Write-Host "   ✅ Found ngrok at: $path" -ForegroundColor Green
        break
    }
}

# If not found, search Downloads for zip file
if (-not $ngrokPath) {
    Write-Host "   Searching Downloads folder..." -ForegroundColor Gray
    $zipFile = Get-ChildItem -Path "$env:USERPROFILE\Downloads" -Filter "*ngrok*.zip" -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if ($zipFile) {
        Write-Host "   Found ngrok zip: $($zipFile.FullName)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   Please extract ngrok.exe from the zip file." -ForegroundColor Yellow
        Write-Host "   Recommended location: C:\ngrok\" -ForegroundColor White
        Write-Host ""
        $extracted = Read-Host "   Press Enter after extracting, or type the path to ngrok.exe"
        
        if ($extracted -and $extracted -ne "") {
            if (Test-Path $extracted) {
                $ngrokPath = $extracted
            }
        } else {
            # Check if they extracted to C:\ngrok\
            if (Test-Path "C:\ngrok\ngrok.exe") {
                $ngrokPath = "C:\ngrok\ngrok.exe"
            }
        }
    }
}

# If still not found, ask user
if (-not $ngrokPath) {
    Write-Host "   ❌ ngrok.exe not found automatically" -ForegroundColor Red
    Write-Host ""
    Write-Host "   Please provide the full path to ngrok.exe" -ForegroundColor Yellow
    Write-Host "   Example: C:\ngrok\ngrok.exe" -ForegroundColor Gray
    Write-Host ""
    $userPath = Read-Host "   Enter path to ngrok.exe (or press Enter to skip)"
    
    if ($userPath -and (Test-Path $userPath)) {
        $ngrokPath = $userPath
    } else {
        Write-Host "   ❌ ngrok.exe not found. Please extract it and run this script again." -ForegroundColor Red
        exit 1
    }
}

Write-Host ""

# Step 2: Check/Configure authtoken
Write-Host "[2/4] Checking ngrok authtoken..." -ForegroundColor Yellow

$ngrokConfig = "$env:USERPROFILE\.ngrok2\ngrok.yml"
$needsToken = $true

if (Test-Path $ngrokConfig) {
    $configContent = Get-Content $ngrokConfig -Raw
    if ($configContent -match "authtoken:\s+[a-zA-Z0-9_]+") {
        Write-Host "   ✅ ngrok authtoken is already configured" -ForegroundColor Green
        $needsToken = $false
    }
}

if ($needsToken) {
    Write-Host "   ⚠️  ngrok authtoken is NOT configured" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Please:" -ForegroundColor Yellow
    Write-Host "   1. Go to: https://dashboard.ngrok.com/signup" -ForegroundColor White
    Write-Host "   2. Sign up (if you haven't)" -ForegroundColor White
    Write-Host "   3. Get your token: https://dashboard.ngrok.com/get-started/your-authtoken" -ForegroundColor White
    Write-Host ""
    $token = Read-Host "   Enter your ngrok authtoken"
    
    if ($token) {
        Write-Host "   Configuring ngrok..." -ForegroundColor Gray
        & $ngrokPath config add-authtoken $token
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ ngrok authtoken configured successfully" -ForegroundColor Green
        } else {
            Write-Host "   ❌ Failed to configure authtoken" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "   ⚠️  Skipping authtoken configuration" -ForegroundColor Yellow
        Write-Host "   You'll need to run: $ngrokPath config add-authtoken YOUR_TOKEN" -ForegroundColor Gray
    }
}

Write-Host ""

# Step 3: Check if backend is running
Write-Host "[3/4] Checking backend server..." -ForegroundColor Yellow
$portCheck = Get-NetTCPConnection -LocalPort 5050 -ErrorAction SilentlyContinue
if ($portCheck) {
    Write-Host "   ✅ Backend is running on port 5050" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Backend is NOT running on port 5050" -ForegroundColor Yellow
    Write-Host "   Please start your backend in another terminal: npm run dev" -ForegroundColor White
}
Write-Host ""

# Step 4: Start ngrok
Write-Host "[4/4] Ready to start ngrok!" -ForegroundColor Yellow
Write-Host ""
Write-Host "   ngrok path: $ngrokPath" -ForegroundColor Gray
Write-Host ""
Write-Host "   Starting ngrok tunnel on port 5050..." -ForegroundColor Cyan
Write-Host "   ⚠️  Keep this window open!" -ForegroundColor Yellow
Write-Host "   📋 Copy the 'Forwarding' URL when it appears" -ForegroundColor Yellow
Write-Host ""
Write-Host "   Press Ctrl+C to stop ngrok" -ForegroundColor Gray
Write-Host ""

# Start ngrok
& $ngrokPath http 5050


