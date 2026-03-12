# Version 1.0
# LLM Triage Prompt Generator
Clear-Host
Write-Host "=== LLM Triage Prompt Generator ===" -ForegroundColor Cyan
Write-Host "Press Enter to skip any fields you don't have.`n"

# 1. Alert Metadata
Write-Host "[1/4] Alert Metadata" -ForegroundColor Yellow
$alertName = Read-Host "Alert name"
$alertSource = Read-Host "Alert Source (e.g., EDR/Firewall/SIEM)"
$otherAlerts = Read-Host "Other alerts?"

# 2. Host Entity Context
Write-Host "`n[2/4] Host Entity Context/Location" -ForegroundColor Yellow
$hostOS = Read-Host "Host OS"
$hostCriticality = Read-Host "Host criticality (e.g., Tier 0, Workstation)"
$hostLocation = Read-Host "Host location (e.g., On-prem/Cloud)"

# 3. User Entity
Write-Host "`n[3/4] User Entity/Location" -ForegroundColor Yellow
$userRole = Read-Host "What is this user's role?"
$sourceIp = Read-Host "Is there a source IP for this detection?"

# 4. Raw Telemetry
Write-Host "`n[4/4] Raw Telemetry" -ForegroundColor Yellow
$uploadLog = Read-Host "Will a log or file be uploaded directly to the AI separately? (Y/N)"

$rawTelemetry = ""

if ($uploadLog -match "^[Nn]") {
    Write-Host "Paste the raw log or context below. (Press Enter on an empty line when finished):" -ForegroundColor DarkGray
    
    # Allows for multi-line pasting (crucial for JSON logs)
    $rawTelemetryText = @()
    while ($true) {
        $line = Read-Host
        if ([string]::IsNullOrWhiteSpace($line)) { break }
        $rawTelemetryText += $line
    }
    $rawTelemetry = $rawTelemetryText -join "`n"
} else {
    $rawTelemetry = "[Review the attached file for raw telemetry]"
}

# Construct the XML Template
$xmlPrompt = @"
<instructions>
You are an expert Security Operations Analyst. Review the following alert context and determine the likelihood of a true positive compromise.

Perform the following actions:
1. Analyze the alert context and raw telemetry.
2. Determine if this activity is malicious, benign administrative behavior, or a false positive. Provide a brief justification.
3. Extract any key Indicators of Compromise (IoCs).
4. Recommend immediate next steps for containment or investigation.
</instructions>

<alert_metadata>
Alert Name: $alertName
Alert Source: $alertSource
Related Alerts: $otherAlerts
</alert_metadata>

<host_entity_context>
Host OS: $hostOS
Host Criticality: $hostCriticality
Host Location: $hostLocation
</host_entity_context>

<user_entity_context>
User Role: $userRole
Source IP: $sourceIp
</user_entity_context>

<raw_telemetry>
$rawTelemetry
</raw_telemetry>
"@

# Copy to clipboard
$xmlPrompt | Set-Clipboard

Write-Host "`n[+] Success! The XML prompt has been generated and copied to your clipboard." -ForegroundColor Green
Write-Host "You can now paste it directly into your AI tool.`n"