# ngrok Setup Script for Google OAuth
# This script helps you set up ngrok for Google OAuth

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ngrok Setup for Google OAuth" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if ngrok is installed
Write-Host "Checking if ngrok is installed..." -ForegroundColor Yellow
$ngrokPath = Get-Command ngrok -ErrorAction SilentlyContinue

if (-not $ngrokPath) {
    Write-Host "❌ ngrok is NOT installed" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please follow these steps:" -ForegroundColor Yellow
    Write-Host "1. Go to: https://ngrok.com/download" -ForegroundColor White
    Write-Host "2. Download ngrok for Windows" -ForegroundColor White
    Write-Host "3. Extract ngrok.exe to a folder (e.g., C:\ngrok\)" -ForegroundColor White
    Write-Host "4. Add that folder to your PATH, OR run this script from that folder" -ForegroundColor White
    Write-Host ""
    Write-Host "Alternatively, if you have Chocolatey:" -ForegroundColor Yellow
    Write-Host "  choco install ngrok" -ForegroundColor White
    Write-Host ""
    Write-Host "Or if you have Scoop:" -ForegroundColor Yellow
    Write-Host "  scoop install ngrok" -ForegroundColor White
    Write-Host ""
    exit 1
} else {
    Write-Host "✅ ngrok is installed at: $($ngrokPath.Source)" -ForegroundColor Green
    Write-Host ""
}

# Check if authtoken is configured
Write-Host "Checking ngrok configuration..." -ForegroundColor Yellow
$ngrokConfig = "$env:USERPROFILE\.ngrok2\ngrok.yml"
if (Test-Path $ngrokConfig) {
    $configContent = Get-Content $ngrokConfig -Raw
    if ($configContent -match "authtoken:") {
        Write-Host "✅ ngrok authtoken is configured" -ForegroundColor Green
    } else {
        Write-Host "⚠️  ngrok authtoken is NOT configured" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Please run:" -ForegroundColor Yellow
        Write-Host "  ngrok config add-authtoken YOUR_TOKEN" -ForegroundColor White
        Write-Host ""
        Write-Host "Get your token from: https://dashboard.ngrok.com/get-started/your-authtoken" -ForegroundColor White
        Write-Host ""
        exit 1
    }
} else {
    Write-Host "⚠️  ngrok authtoken is NOT configured" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please run:" -ForegroundColor Yellow
    Write-Host "  ngrok config add-authtoken YOUR_TOKEN" -ForegroundColor White
    Write-Host ""
    Write-Host "Get your token from: https://dashboard.ngrok.com/get-started/your-authtoken" -ForegroundColor White
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "✅ ngrok is ready to use!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Make sure your backend is running on port 5050" -ForegroundColor White
Write-Host "2. Run: ngrok http 5050" -ForegroundColor White
Write-Host "3. Copy the ngrok URL (e.g., https://abc123.ngrok-free.app)" -ForegroundColor White
Write-Host "4. Use that URL in Google Console and your .env file" -ForegroundColor White
Write-Host ""


