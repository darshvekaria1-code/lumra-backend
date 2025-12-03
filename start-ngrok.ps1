# Start ngrok tunnel for Google OAuth
# Make sure your backend is running on port 5050 first!

$ngrokPath = "C:\ngrok\ngrok.exe"

if (-not (Test-Path $ngrokPath)) {
    Write-Host "❌ ngrok.exe not found at $ngrokPath" -ForegroundColor Red
    Write-Host "Please extract ngrok.exe to C:\ngrok\" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting ngrok Tunnel" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if backend is running
$portCheck = Get-NetTCPConnection -LocalPort 5050 -ErrorAction SilentlyContinue
if (-not $portCheck) {
    Write-Host "⚠️  WARNING: Nothing is running on port 5050!" -ForegroundColor Red
    Write-Host "   Make sure your backend server is running first." -ForegroundColor Yellow
    Write-Host "   Run: npm run dev" -ForegroundColor White
    Write-Host ""
    $continue = Read-Host "   Continue anyway? (y/n)"
    if ($continue -ne "y") {
        exit 1
    }
}

Write-Host "Starting ngrok tunnel on port 5050..." -ForegroundColor Yellow
Write-Host ""
Write-Host "⚠️  IMPORTANT: Keep this window open!" -ForegroundColor Yellow
Write-Host "⚠️  Copy the 'Forwarding' URL (e.g., https://abc123.ngrok-free.app)" -ForegroundColor Yellow
Write-Host "⚠️  Use that URL in Google Console and your .env file" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop ngrok" -ForegroundColor Gray
Write-Host ""

# Start ngrok
& $ngrokPath http 5050
