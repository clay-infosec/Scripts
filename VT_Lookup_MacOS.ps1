# Author: Clay Clement  
# Version: 1.0
# Description: Powershell cmdlet that allows you to cross check the hash of your most recent file in downloads folder (MacOS)
# Once added to your PS profile, cmdlet is 'Get-VirusTotal'

function Get-VirusTotal {
    [CmdletBinding()]
    param()

    # --- Configuration ---
    $apiKey = 'API Key Here'
    
    # Use $HOME for macOS compatibility
    $downloadsPath = "$HOME/Downloads"

    # 1. Locate the latest file
    if (-not (Test-Path $downloadsPath)) {
        Write-Error "Could not find Downloads folder at $downloadsPath"
        return
    }

    $latestFile = Get-ChildItem -Path $downloadsPath -File | 
                   Sort-Object LastWriteTime -Descending | 
                   Select-Object -First 1

    if ($null -eq $latestFile) {
        Write-Warning "No files found in $downloadsPath"
        return
    }

    $filePath = $latestFile.FullName
    Write-Host "Targeting: $($latestFile.Name)" -ForegroundColor Magenta
    
    # 2. Hash and Query
    try {
        # Get-FileHash works on PowerShell Core for Mac
        $fileHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
        
        $uri = "https://www.virustotal.com/api/v3/files/$fileHash"
        $headers = @{ 
            "x-apikey" = $apiKey
            "accept"   = "application/json" 
        }

        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        $stats = $response.data.attributes.last_analysis_stats
        
        Write-Host "`n--- VirusTotal Results ---" -ForegroundColor Yellow
        Write-Host "Malicious:    $($stats.malicious)" -ForegroundColor Red
        Write-Host "Suspicious:   $($stats.suspicious)" -ForegroundColor DarkYellow
        Write-Host "Undetected:   $($stats.undetected)" -ForegroundColor Green
        Write-Host "`nFull Report: https://www.virustotal.com/gui/file/$fileHash"
    }
    catch {
        # Check for 404 specifically
        if ($_.Exception.Message -match "404") {
            Write-Warning "Hash not found in VirusTotal database."
        } else {
            Write-Error "Error: $($_.Exception.Message)"
        }
    }
}