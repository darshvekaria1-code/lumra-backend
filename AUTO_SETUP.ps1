# Automated Setup Script for Google OAuth with ngrok
# Run this script to set everything up automatically

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Lumra AI - Google OAuth Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check .env file
Write-Host "[1/6] Checking .env file..." -ForegroundColor Yellow
if (-not (Test-Path .env)) {
    Write-Host "   Creating .env file from template..." -ForegroundColor Gray
    Copy-Item env.example .env
    Write-Host "   ✅ Created .env file" -ForegroundColor Green
} else {
    Write-Host "   ✅ .env file exists" -ForegroundColor Green
}
Write-Host ""

# Step 2: Check ngrok installation
Write-Host "[2/6] Checking ngrok installation..." -ForegroundColor Yellow
$ngrokPath = Get-Command ngrok -ErrorAction SilentlyContinue
if (-not $ngrokPath) {
    Write-Host "   ❌ ngrok is NOT installed" -ForegroundColor Red
    Write-Host ""
    Write-Host "   Please install ngrok:" -ForegroundColor Yellow
    Write-Host "   1. Go to: https://ngrok.com/download" -ForegroundColor White
    Write-Host "   2. Download and extract ngrok.exe" -ForegroundColor White
    Write-Host "   3. Add to PATH or run from that folder" -ForegroundColor White
    Write-Host ""
    Write-Host "   OR use Chocolatey: choco install ngrok" -ForegroundColor White
    Write-Host ""
    $continue = Read-Host "   Press Enter after installing ngrok, or type 'skip' to continue"
    if ($continue -eq "skip") {
        Write-Host "   ⚠️  Skipping ngrok check" -ForegroundColor Yellow
    } else {
        $ngrokPath = Get-Command ngrok -ErrorAction SilentlyContinue
        if (-not $ngrokPath) {
            Write-Host "   ❌ ngrok still not found. Please install it and run this script again." -ForegroundColor Red
            exit 1
        }
    }
}

if ($ngrokPath) {
    Write-Host "   ✅ ngrok is installed at: $($ngrokPath.Source)" -ForegroundColor Green
}
Write-Host ""

# Step 3: Check ngrok authtoken
Write-Host "[3/6] Checking ngrok configuration..." -ForegroundColor Yellow
$ngrokConfig = "$env:USERPROFILE\.ngrok2\ngrok.yml"
$authtokenConfigured = $false

if (Test-Path $ngrokConfig) {
    $configContent = Get-Content $ngrokConfig -Raw
    if ($configContent -match "authtoken:") {
        $authtokenConfigured = $true
        Write-Host "   ✅ ngrok authtoken is configured" -ForegroundColor Green
    }
}

if (-not $authtokenConfigured) {
    Write-Host "   ⚠️  ngrok authtoken is NOT configured" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Please:" -ForegroundColor Yellow
    Write-Host "   1. Sign up at: https://dashboard.ngrok.com/signup" -ForegroundColor White
    Write-Host "   2. Get your token from: https://dashboard.ngrok.com/get-started/your-authtoken" -ForegroundColor White
    Write-Host "   3. Run: ngrok config add-authtoken YOUR_TOKEN" -ForegroundColor White
    Write-Host ""
    $token = Read-Host "   Enter your ngrok authtoken (or press Enter to skip)"
    if ($token) {
        Write-Host "   Configuring ngrok..." -ForegroundColor Gray
        & ngrok config add-authtoken $token
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ ngrok authtoken configured" -ForegroundColor Green
        } else {
            Write-Host "   ❌ Failed to configure authtoken" -ForegroundColor Red
        }
    } else {
        Write-Host "   ⚠️  Skipping authtoken configuration" -ForegroundColor Yellow
    }
}
Write-Host ""

# Step 4: Check if backend is running
Write-Host "[4/6] Checking backend server..." -ForegroundColor Yellow
$portCheck = Get-NetTCPConnection -LocalPort 5050 -ErrorAction SilentlyContinue
if ($portCheck) {
    Write-Host "   ✅ Backend is running on port 5050" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Backend is NOT running on port 5050" -ForegroundColor Yellow
    Write-Host "   Please start your backend: npm run dev" -ForegroundColor White
}
Write-Host ""

# Step 5: Check .env configuration
Write-Host "[5/6] Checking .env configuration..." -ForegroundColor Yellow
$envContent = Get-Content .env -Raw
$needsGoogleConfig = $false

if (-not ($envContent -match "GOOGLE_CLIENT_ID=.*[a-zA-Z0-9]")) {
    $needsGoogleConfig = $true
    Write-Host "   ⚠️  GOOGLE_CLIENT_ID not configured" -ForegroundColor Yellow
}
if (-not ($envContent -match "GOOGLE_CLIENT_SECRET=.*[a-zA-Z0-9]")) {
    $needsGoogleConfig = $true
    Write-Host "   ⚠️  GOOGLE_CLIENT_SECRET not configured" -ForegroundColor Yellow
}

if ($needsGoogleConfig) {
    Write-Host ""
    Write-Host "   Please configure Google OAuth:" -ForegroundColor Yellow
    Write-Host "   1. Go to: https://console.cloud.google.com/apis/credentials" -ForegroundColor White
    Write-Host "   2. Create OAuth 2.0 Client ID" -ForegroundColor White
    Write-Host "   3. Add your credentials to .env file" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "   ✅ Google OAuth credentials are configured" -ForegroundColor Green
}
Write-Host ""

# Step 6: Summary and next steps
Write-Host "[6/6] Setup Summary" -ForegroundColor Yellow
Write-Host ""
Write-Host "✅ Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Start ngrok tunnel:" -ForegroundColor White
Write-Host "   .\start-ngrok.ps1" -ForegroundColor Gray
Write-Host "   OR: ngrok http 5050" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Copy the ngrok URL (e.g., https://abc123.ngrok-free.app)" -ForegroundColor White
Write-Host ""
Write-Host "3. Update Google Console:" -ForegroundColor White
Write-Host "   - Application home page: https://abc123.ngrok-free.app" -ForegroundColor Gray
Write-Host "   - Redirect URI: https://abc123.ngrok-free.app/api/auth/google/callback" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Update .env file:" -ForegroundColor White
Write-Host "   GOOGLE_CALLBACK_URL=https://abc123.ngrok-free.app/api/auth/google/callback" -ForegroundColor Gray
Write-Host ""
Write-Host "5. Restart backend server" -ForegroundColor White
Write-Host ""
Write-Host "For detailed instructions, see: QUICK_SETUP.md" -ForegroundColor Gray
Write-Host ""


