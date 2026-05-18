{\rtf1\ansi\ansicpg1252\cocoartf2868
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 function Get-VTIPReputation \{\
    [CmdletBinding(DefaultParameterSetName = 'Single')]\
    param(\
        [Parameter(ParameterSetName = 'Single', Position = 0, Mandatory = $false, ValueFromPipeline = $true)]\
        [string]$IPAddress,\
\
        [Parameter(ParameterSetName = 'Bulk', Mandatory = $true)]\
        [switch]$Bulk,\
\
        [Parameter(Mandatory = $false)]\
        [string]$ApiKey = "YOUR_VT_API_KEY_HERE" # Replace with your actual key or use $env:VT_API_KEY\
    )\
\
    begin \{\
        # Check for API key\
        if ([string]::IsNullOrWhiteSpace($ApiKey) -or $ApiKey -eq "YOUR_VT_API_KEY_HERE") \{\
            Write-Error "VirusTotal API Key is missing. Please populate the `$ApiKey parameter or update the script default."\
            return\
        \}\
\
        $Headers = @\{\
            "x-apikey" = $ApiKey\
        \}\
\
        # Helper function to query VirusTotal V3 API\
        function Invoke-VTLookup \{\
            param([string]$IP)\
            \
            # Basic IPv4/IPv6 regex validation to save API bandwidth\
            if ($IP -notmatch '^\\d\{1,3\}(\\.\\d\{1,3\})\{3\}$' -and $IP -notmatch ':') \{\
                Write-Warning "Skipping invalid IP format: $IP"\
                return $null\
            \}\
\
            $Url = "https://www.virustotal.com/api/v3/ip_addresses/$IP"\
            try \{\
                $Response = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get -ErrorAction Stop\
                \
                $Stats = $Response.data.attributes.last_analysis_stats\
                $Score = "$($Stats.malicious)/$($Stats.malicious + $Stats.suspicious + $Stats.harmless + $Stats.undetected)"\
                \
                [PSCustomObject]@\{\
                    IPAddress  = $IP\
                    Reputation = $Score\
                    ASN        = $Response.data.attributes.asn\
                    AS_Label   = $Response.data.attributes.as_owner\
                \}\
            \}\
            catch \{\
                if ($_.Exception.Response.StatusCode.value__ -eq 404) \{\
                    # VT returns 404 if it has absolutely no record of the IP\
                    [PSCustomObject]@\{\
                        IPAddress  = $IP\
                        Reputation = "No Record (0/0)"\
                        ASN        = "N/A"\
                        AS_Label   = "Unknown"\
                    \}\
                \}\
                elseif ($_.Exception.Response.StatusCode.value__ -eq 429) \{\
                    Write-Error "Rate limit exceeded (HTTP 429). Free VT API is limited to 4 requests/min."\
                    return "RATE_LIMITED"\
                \}\
                else \{\
                    Write-Error "Error querying IP $IP : $($_.Exception.Message)"\
                    return $null\
                \}\
            \}\
        \}\
    \}\
\
    process \{\
        if ($Bulk) \{\
            # Bring up Windows File Explorer GUI to select CSV\
            Add-Type -AssemblyName System.Windows.Forms\
            $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @\{\
                InitialDirectory = [Environment]::GetFolderPath('Desktop')\
                Filter           = "CSV Files (*.csv)|*.csv"\
                Title            = "Select IP List CSV File"\
            \}\
\
            if ($FileBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) \{\
                $CsvPath = $FileBrowser.FileName\
                Write-Host "Loading: $CsvPath" -ForegroundColor Cyan\
                \
                $Data = Import-Csv -Path $CsvPath\
                \
                # Dynamically identify the IP column name (handles 'IP', 'IPAddress', 'ip_address', etc.)\
                $FirstRow = $Data[0]\
                $IpColumn = ($FirstRow.psobject.Properties.Name | Where-Object \{ $_ -match 'ip' \})[0]\
\
                if (-not $IpColumn) \{\
                    # Fallback to the very first column if no column contains 'ip' in the name\
                    $IpColumn = $FirstRow.psobject.Properties.Name[0]\
                    Write-Warning "No explicit 'IP' column header detected. Using the first column: [$IpColumn]"\
                \}\
\
                $Results = [System.Collections.Generic.List[PSCustomObject]]::new()\
                \
                Write-Host "Processing IPs against VirusTotal... (Press Ctrl+C to abort)" -ForegroundColor Yellow\
                foreach ($Row in $Data) \{\
                    $CurrentIP = $Row.$IpColumn\
                    if ([string]::IsNullOrWhiteSpace($CurrentIP)) \{ continue \}\
\
                    $Output = Invoke-VTLookup -IP $CurrentIP\
                    if ($Output -eq "RATE_LIMITED") \{ break \}\
                    if ($Output) \{ $Results.Add($Output) \}\
\
                    # Operational Safety: If using a free API key, consider uncommenting the line below \
                    # to prevent instantly slamming into the 4 req/min wall.\
                    # Start-Sleep -Seconds 15 \
                \}\
\
                # Output the final table to console\
                $Results | Format-Table -AutoSize\
            \}\
            else \{\
                Write-Warning "File selection canceled."\
            \}\
        \}\
        else \{\
            # Single Mode Execution\
            if ([string]::IsNullOrWhiteSpace($IPAddress)) \{\
                $IPAddress = Read-Host "Enter IP Address to check"\
            \}\
            \
            $Result = Invoke-VTLookup -IP $IPAddress\
            if ($Result) \{ $Result | Format-List \}\
        \}\
    \}\
\}}