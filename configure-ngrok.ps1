# Configure ngrok authtoken
# Run this after you get your authtoken from https://dashboard.ngrok.com/get-started/your-authtoken

$ngrokPath = "C:\ngrok\ngrok.exe"

if (-not (Test-Path $ngrokPath)) {
    Write-Host "❌ ngrok.exe not found at $ngrokPath" -ForegroundColor Red
    Write-Host "Please extract ngrok.exe to C:\ngrok\" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Configure ngrok Authtoken" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Go to: https://dashboard.ngrok.com/signup" -ForegroundColor Yellow
Write-Host "2. Sign up (if you haven't)" -ForegroundColor Yellow
Write-Host "3. Get your token: https://dashboard.ngrok.com/get-started/your-authtoken" -ForegroundColor Yellow
Write-Host ""
$token = Read-Host "Enter your ngrok authtoken"

if ($token) {
    Write-Host ""
    Write-Host "Configuring ngrok..." -ForegroundColor Gray
    & $ngrokPath config add-authtoken $token
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "✅ ngrok authtoken configured successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next step: Run start-ngrok.ps1 to start the tunnel" -ForegroundColor Cyan
    } else {
        Write-Host ""
        Write-Host "❌ Failed to configure authtoken" -ForegroundColor Red
        Write-Host "Make sure you copied the token correctly" -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "⚠️  No token provided" -ForegroundColor Yellow
}


