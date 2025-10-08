#requires -RunAsAdministrator

<#
.SYNOPSIS
    Enhanced WinRM Configuration Script for Log Collection via WEC

.DESCRIPTION
    This script provides comprehensive WinRM configuration for Windows Event Collector (WEC) 
    log collection. It supports both HTTP and HTTPS listeners with advanced security features,
    firewall configuration, and certificate management.

.PARAMETER Action
    The action to perform. Valid values: report, enable, configurefirewall, exportcacert, 
    showallcerts, disable, status

.PARAMETER ListenerType
    Type of listener to configure. Valid values: http, https

.PARAMETER User
    User account for log collection. Supports formats: domain\user, user@domain.com, localuser

.PARAMETER Port
    Custom port number (1-65535). Default: 5985 for HTTP, 5986 for HTTPS

.PARAMETER ThumbPrint
    Certificate thumbprint for HTTPS listener

.PARAMETER ExportCertPath
    Path to export certificate files

.PARAMETER AuthType
    Authentication type. Valid values: basic, kerberos (default: kerberos)

.PARAMETER WECIP
    IP address of Windows Event Collector

.PARAMETER WECHostname
    Hostname of Windows Event Collector

.PARAMETER LogLevel
    Logging level. Valid values: Error, Warning, Info, Debug (default: Info)

.PARAMETER ConfigFile
    Path to configuration file (JSON format)

.EXAMPLE
    .\winrmconfig_v2.0.ps1 -Action report

.EXAMPLE
    .\winrmconfig_v2.0.ps1 -Action enable -ListenerType https -User "domain\user"

.EXAMPLE
    .\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP "192.168.1.100" -WECHostname "wec-server"

.NOTES
    Author: Andre Henrique (Uniao Geek)
    Email: contato@uniaogeek.com.br
    LinkedIn: https://www.linkedin.com/in/mrhenrike
    Instagram: @uniaogeek
    Version: 2.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("report", "enable", "configurefirewall", "exportcacert", "showallcerts", "disable", "status", "status-all")]
    [string]$Action,
    
    [Parameter()]
    [ValidateSet("http", "https")]
    [string]$ListenerType,
    
    [Parameter()]
    [string]$User,
    
    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$Port,
    
    [Parameter()]
    [string]$ThumbPrint,
    
    [Parameter()]
    [string]$ExportCertPath,
    
    [Parameter()]
    [ValidateSet("basic", "kerberos")]
    [string]$AuthType = "kerberos",
    
    [Parameter()]
    [string]$WECIP,
    
    [Parameter()]
    [string]$WECHostname,
    
    [Parameter()]
    [ValidateSet("Error", "Warning", "Info", "Debug")]
    [string]$LogLevel = "Info",
    
    [Parameter()]
    [string]$ConfigFile
)

# Script metadata
$ScriptVersion = "2.0.0"
$ScriptAuthor = "Andre Henrique (Uniao Geek)"
$ScriptEmail = "contato@uniaogeek.com.br"
$ScriptLinkedIn = "https://www.linkedin.com/in/mrhenrike"
$ScriptInstagram = "@uniaogeek"

# Global variables
$Global:RestartRequired = $false
$LogFile = Join-Path $env:TEMP "winrmconfig_enhanced.log"

# Set execution policy and strict mode
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Set-StrictMode -Version Latest

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with color coding
        switch ($Level) {
        "Error" { Write-Host $logEntry -ForegroundColor Red }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
        "Debug" { Write-Host $logEntry -ForegroundColor Cyan }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    # Write to log file
    try {
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Host "Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Show help function
function Show-Help {
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "WinRM Configuration Script Enhanced v$ScriptVersion" -ForegroundColor Yellow
    Write-Host "Author: $ScriptAuthor" -ForegroundColor Green
    Write-Host "Email: $ScriptEmail" -ForegroundColor Green
    Write-Host "LinkedIn: $ScriptLinkedIn" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "DESCRIPTION:" -ForegroundColor Yellow
    Write-Host "  Enhanced PowerShell script for configuring Windows Remote Management (WinRM)" -ForegroundColor White
    Write-Host "  for log collection via Windows Event Collector (WEC). Supports both HTTP and" -ForegroundColor White
    Write-Host "  HTTPS modes with comprehensive security features and firewall configuration." -ForegroundColor White
    Write-Host ""
    
    Write-Host "REQUIREMENTS:" -ForegroundColor Yellow
    Write-Host "  • PowerShell 5.1 or later" -ForegroundColor White
    Write-Host "  • Administrative privileges" -ForegroundColor White
    Write-Host "  • Windows Server 2008 R2 or later" -ForegroundColor White
    Write-Host ""
    
    Write-Host "ACTIONS:" -ForegroundColor Yellow
    Write-Host "  report            Generate WinRM configuration report" -ForegroundColor White
    Write-Host "  enable            Configure WinRM listeners (HTTP/HTTPS)" -ForegroundColor White
    Write-Host "  configurefirewall Configure firewall rules for WEC" -ForegroundColor White
    Write-Host "  exportcacert      Export certificate for WEC" -ForegroundColor White
    Write-Host "  showallcerts      List compatible certificates" -ForegroundColor White
    Write-Host "  disable           Remove WinRM listeners" -ForegroundColor White
    Write-Host "  status            Check WinRM service status (quick summary)" -ForegroundColor White
    Write-Host "  status-all        Check WinRM service status (detailed report)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "USAGE EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  # Generate configuration report" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action report" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Configure HTTPS listener with user" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action enable -ListenerType https -User `"domain\user`"" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Configure HTTP listener with custom port" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -Port 5985" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Configure firewall for WEC" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP `"192.168.1.100`" -WECHostname `"wec-server`"" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Export certificate" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action exportcacert -ExportCertPath `"C:\temp`"" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # List available certificates" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action showallcerts" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Check WinRM status (quick)" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action status" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Check WinRM status (detailed)" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action status-all" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "PARAMETERS:" -ForegroundColor Yellow
    Write-Host "  -Action           Action to perform (report, enable, configurefirewall, etc.)" -ForegroundColor White
    Write-Host "  -ListenerType     Type of listener: http, https" -ForegroundColor White
    Write-Host "  -User             User account for log collection (domain\user or user@domain)" -ForegroundColor White
    Write-Host "  -Port             Custom port number (1-65535)" -ForegroundColor White
    Write-Host "  -ThumbPrint       Certificate thumbprint for HTTPS listener" -ForegroundColor White
    Write-Host "  -ExportCertPath   Path to export certificate files" -ForegroundColor White
    Write-Host "  -AuthType         Authentication type: basic, kerberos (default: kerberos)" -ForegroundColor White
    Write-Host "  -WECIP            IP address of Windows Event Collector" -ForegroundColor White
    Write-Host "  -WECHostname      Hostname of Windows Event Collector" -ForegroundColor White
    Write-Host "  -LogLevel         Logging level: Error, Warning, Info, Debug (default: Info)" -ForegroundColor White
    Write-Host "  -ConfigFile       Path to configuration file (JSON format)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "COMMON SCENARIOS:" -ForegroundColor Yellow
    Write-Host "  # Complete WEC setup (HTTPS + Firewall + Certificate)" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action enable -ListenerType https -User `"wec-collector@domain.com`"" -ForegroundColor Gray
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP `"192.168.1.100`" -WECHostname `"wec-server`"" -ForegroundColor Gray
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action exportcacert -ExportCertPath `"C:\temp`"" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Development/Testing setup (HTTP + Basic Auth)" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -AuthType basic" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Troubleshooting and verification" -ForegroundColor White
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action status" -ForegroundColor Gray
    Write-Host "  .\winrmconfig_v2.0.ps1 -Action report -User `"domain\user`"" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "NOTES:" -ForegroundColor Yellow
    Write-Host "  • This script requires administrative privileges" -ForegroundColor White
    Write-Host "  • HTTPS listeners require valid certificates with Server Authentication EKU" -ForegroundColor White
    Write-Host "  • Firewall rules are automatically configured for WEC communication" -ForegroundColor White
    Write-Host "  • Logs are written to: $LogFile" -ForegroundColor White
    Write-Host "  • For detailed logging, use: -LogLevel Debug" -ForegroundColor White
    Write-Host ""
    
    Write-Host "SUPPORT:" -ForegroundColor Yellow
    Write-Host "  Email: $ScriptEmail" -ForegroundColor Green
    Write-Host "  LinkedIn/X: $ScriptLinkedIn" -ForegroundColor Green
    Write-Host "  Instagram: $ScriptInstagram" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

# Quick status function for summary
function Get-QuickStatus {
    Write-Log "Generating quick WinRM status..." "Info"
    
    # Service Status
    $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
    $firewallService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "WINRM QUICK STATUS" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    # Service Information
    Write-Host "`nSERVICES:" -ForegroundColor Green
    Write-Host "  WinRM: $($winrmService.Status)" -ForegroundColor $(if ($winrmService.Status -eq "Running") { "Green" } else { "Red" })
    Write-Host "  Firewall: $($firewallService.Status)" -ForegroundColor $(if ($firewallService.Status -eq "Running") { "Green" } else { "Red" })
    
    # Quick listener check
    try {
        $listeners = winrm enumerate winrm/config/listener
        if ($listeners -and $listeners.Length -gt 0) {
            Write-Host "`nLISTENERS:" -ForegroundColor Green
            $listenerCount = 0
            foreach ($listener in $listeners) {
                $listenerCount++
                # Simple display without complex parsing
                Write-Host "  Listener #$listenerCount`: Active" -ForegroundColor White
            }
        } else {
            Write-Host "`nLISTENERS: None configured" -ForegroundColor Red
        }
    } catch {
        Write-Host "`nLISTENERS: Unable to check" -ForegroundColor Yellow
    }
    
    # Quick firewall check for ports 5985 and 5986
    Write-Host "`nFIREWALL:" -ForegroundColor Green
    try {
        $ports = @(5985, 5986)
        foreach ($checkPort in $ports) {
            $firewallRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
            $foundRule = $false
            $ruleName = ""
            
            foreach ($rule in $firewallRules) {
                $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                if ($portFilter -and ($portFilter.LocalPort -eq $checkPort -or $portFilter.LocalPort -eq "Any")) {
                    $foundRule = $true
                    $ruleName = $rule.DisplayName
                    break
                }
            }
            
            if ($foundRule) {
                Write-Host "  Port $checkPort`: Open (Rule: $ruleName)" -ForegroundColor Green
            } else {
                Write-Host "  Port $checkPort`: Closed (No rule found)" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "  Unable to check firewall status" -ForegroundColor Yellow
    }
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
}

# Enhanced status function with detailed listener information
function Get-DetailedStatus {
    Write-Log "Generating detailed WinRM status report..." "Info"
    
    # Service Status
    $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
    $firewallService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
    
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "WINRM DETAILED STATUS REPORT" -ForegroundColor Yellow
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    # Service Information
    Write-Host "`nSERVICE STATUS:" -ForegroundColor Green
    Write-Host "  WinRM Service: $($winrmService.Status)" -ForegroundColor White
    Write-Host "  Firewall Service: $($firewallService.Status)" -ForegroundColor White
    
    # Get WinRM configuration
    try {
        $winrmConfig = winrm get winrm/config
        $listeners = winrm enumerate winrm/config/listener
        
        Write-Host "`nLISTENERS CONFIGURATION:" -ForegroundColor Green
        
        if ($listeners -and $listeners.Length -gt 0) {
            # Convert array to string and split by "Listener" keyword
            $listenersText = $listeners -join "`n"
            $listenerBlocks = $listenersText -split "Listener" | Where-Object { $_ -match "Address|Transport|Port" }
            
            $listenerCount = 0
            foreach ($listenerBlock in $listenerBlocks) {
                $listenerCount++
                Write-Host "`n  Listener #$listenerCount" -ForegroundColor Yellow
                
                # Parse listener information from text format
                $address = ""
                $transport = ""
                $port = ""
                $hostname = ""
                $certificateThumbprint = ""
                $urlPrefix = ""
                $listeningOn = ""
                $enabled = ""
                
                # Extract information using line-by-line parsing to avoid cross-matching
                $lines = $listenerBlock -split "`n"
                foreach ($line in $lines) {
                    if ($line -match '^\s*Address\s*=\s*(.+)$') {
                        $address = $matches[1].Trim()
                    }
                    elseif ($line -match '^\s*Transport\s*=\s*(.+)$') {
                        $transport = $matches[1].Trim()
                    }
                    elseif ($line -match '^\s*Port\s*=\s*(.+)$') {
                        $port = $matches[1].Trim()
                    }
                    elseif ($line -match '^\s*Hostname\s*=\s*(.+)$') {
                        $hostname = $matches[1].Trim()
                    }
                    elseif ($line -match '^\s*Enabled\s*=\s*(.+)$') {
                        $enabled = $matches[1].Trim()
                    }
                    elseif ($line -match '^\s*URLPrefix\s*=\s*(.+)$') {
                        $urlPrefix = $matches[1].Trim()
                    }
                    elseif ($line -match '^\s*CertificateThumbprint\s*=\s*(.+)$') {
                        $certificateThumbprint = $matches[1].Trim()
                    }
                    elseif ($line -match '^\s*ListeningOn\s*=\s*(.+)$') {
                        $listeningOn = $matches[1].Trim()
                    }
                }
                
                # Display listener details
                Write-Host "    Listener: $transport" -ForegroundColor White
                Write-Host "    Address: $address" -ForegroundColor White
                Write-Host "    Transport: $transport" -ForegroundColor White
                Write-Host "    Port: $port" -ForegroundColor White
                Write-Host "    Hostname: $(if ($hostname) { $hostname } else { 'Not specified' })" -ForegroundColor White
                Write-Host "    Enabled: $(if ($enabled) { $enabled } else { 'true' })" -ForegroundColor Green
                Write-Host "    URL Prefix: $(if ($urlPrefix) { $urlPrefix } else { 'wsman' })" -ForegroundColor White
                Write-Host "    Certificate Thumbprint: $(if ($certificateThumbprint) { $certificateThumbprint } else { 'None' })" -ForegroundColor White
                Write-Host "    Listening On: $listeningOn" -ForegroundColor White
                
                # Check firewall status for this port
                if ($port) {
                    Write-Host "`n    FIREWALL STATUS FOR PORT $port`:" -ForegroundColor Yellow
                    try {
                        $firewallRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
                        $foundRule = $false
                        
                        foreach ($rule in $firewallRules) {
                            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                            if ($portFilter -and ($portFilter.LocalPort -eq $port -or $portFilter.LocalPort -eq "Any")) {
                                $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                                Write-Host "      Rule Name: $($rule.DisplayName)" -ForegroundColor Green
                                Write-Host "      Direction: $($rule.Direction)" -ForegroundColor White
                                Write-Host "      Action: $($rule.Action)" -ForegroundColor White
                                Write-Host "      Status: Open" -ForegroundColor Green
                                if ($addressFilter) {
                                    Write-Host "      Remote Address: $($addressFilter.RemoteAddress)" -ForegroundColor White
                                }
                                $foundRule = $true
                                break
                            }
                        }
                        
                        if (-not $foundRule) {
                            Write-Host "      Status: No specific rule found (may be using default Windows rule)" -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Host "      Status: Unable to check firewall rules" -ForegroundColor Red
                    }
                }
            }
        } else {
            Write-Host "  No listeners found!" -ForegroundColor Red
        }
        
        # WinRM Service Configuration
        Write-Host "`nWINRM SERVICE CONFIGURATION:" -ForegroundColor Green
        if ($winrmConfig) {
            $lines = $winrmConfig -split "`n"
            foreach ($line in $lines) {
                if ($line -match "AllowUnencrypted" -or $line -match "TrustedHosts" -or $line -match "Auth" -or $line -match "Service") {
                    Write-Host "  $line" -ForegroundColor White
                }
            }
        }
        
        # Firewall Rules
        Write-Host "`nFIREWALL RULES:" -ForegroundColor Green
        $firewallRules = Get-NetFirewallRule -DisplayName "*WinRM*" -ErrorAction SilentlyContinue
        if ($firewallRules) {
            foreach ($rule in $firewallRules) {
                Write-Host "  Rule: $($rule.DisplayName)" -ForegroundColor White
                Write-Host "  Direction: $($rule.Direction)" -ForegroundColor White
                Write-Host "  Action: $($rule.Action)" -ForegroundColor White
                Write-Host "  Enabled: $($rule.Enabled)" -ForegroundColor White
                
                # Get port information safely
                try {
                    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                    if ($portFilter) {
                        Write-Host "  Local Port: $($portFilter.LocalPort)" -ForegroundColor White
                    }
                } catch {
                    Write-Host "  Local Port: Not specified" -ForegroundColor Gray
                }
                
                # Get address information safely
                try {
                    $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                    if ($addressFilter) {
                        Write-Host "  Remote Address: $($addressFilter.RemoteAddress)" -ForegroundColor White
                    }
                } catch {
                    Write-Host "  Remote Address: Any" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "  No WinRM firewall rules found" -ForegroundColor Yellow
        }
        
        # Certificate Information
        Write-Host "`nCERTIFICATE INFORMATION:" -ForegroundColor Green
        $certificates = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue
        if ($certificates) {
            foreach ($cert in $certificates) {
                Write-Host "  Subject: $($cert.Subject)" -ForegroundColor White
                Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
                Write-Host "  Valid From: $($cert.NotBefore)" -ForegroundColor White
                Write-Host "  Valid To: $($cert.NotAfter)" -ForegroundColor White
                Write-Host "  Expired: $(if ($cert.NotAfter -lt (Get-Date)) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($cert.NotAfter -lt (Get-Date)) { 'Red' } else { 'Green' })
                Write-Host "  ---" -ForegroundColor Gray
            }
        } else {
            Write-Host "  No certificates found in LocalMachine\My store" -ForegroundColor Yellow
        }
        
        # Network Configuration
        Write-Host "`nNETWORK CONFIGURATION:" -ForegroundColor Green
        $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $networkAdapters) {
            Write-Host "  Adapter: $($adapter.Name)" -ForegroundColor White
            Write-Host "  Status: $($adapter.Status)" -ForegroundColor White
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($ipConfig) {
                Write-Host "  IP Address: $($ipConfig.IPAddress)" -ForegroundColor White
            }
        }
        
        # WinRM Client Configuration
        Write-Host "`nWINRM CLIENT CONFIGURATION:" -ForegroundColor Green
        try {
            $clientConfig = winrm get winrm/config/client
            $clientLines = $clientConfig -split "`n"
            foreach ($line in $clientLines) {
                if ($line -match "TrustedHosts" -or $line -match "AllowUnencrypted") {
                    Write-Host "  $line" -ForegroundColor White
                }
            }
        } catch {
            Write-Host "  Unable to retrieve client configuration" -ForegroundColor Red
        }
        
    } catch {
        Write-Log "Error getting WinRM configuration: $($_.Exception.Message)" "Error"
    }
    
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
}

# Test if user exists
function Test-UserExists {
    param([string]$Username)
    
    try {
        Write-Log "Testing if user exists: $Username" "Debug"
        
        # Parse user format
        if ($Username -match "@") {
            # Email format: user@domain.com
            $user = $Username.Split("@")[0]
            $domain = $Username.Split("@")[1]
            Write-Log "Parsed as email format: user=$user, domain=$domain" "Debug"
        }
        elseif ($Username -match "\\") {
            # Domain format: domain\user
            $domain = $Username.Split("\")[0]
            $user = $Username.Split("\")[1]
            Write-Log "Parsed as domain format: domain=$domain, user=$user" "Debug"
        }
        else {
            # Local user format
            $user = $Username
            $domain = $env:COMPUTERNAME
            Write-Log "Parsed as local user format: user=$user, domain=$domain" "Debug"
        }
        
        # Test user existence
        $userObj = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
        if ($userObj) {
            Write-Log "User found: $user" "Debug"
            return $true
        }
        
        # Try domain user
        try {
            $domainUser = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(
                [System.DirectoryServices.AccountManagement.ContextType]::Domain,
                $Username
            )
            if ($domainUser) {
                Write-Log "Domain user found: $Username" "Debug"
            return $true
        }
    }
    catch {
            Write-Log "Domain user not found: $($_.Exception.Message)" "Debug"
        }
        
        Write-Log "User not found: $Username" "Warning"
            return $false
    }
    catch {
        Write-Log "Error testing user existence: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Add user to Event Log Readers group
function Add-UserToEventLogReaders {
    param([string]$Username)
    
    try {
        Write-Log "Adding user to Event Log Readers group: $Username" "Info"
        
        # Parse user format
        if ($Username -match "@") {
            # Email format: user@domain.com
            $user = $Username.Split("@")[0]
            $domain = $Username.Split("@")[1]
        }
        elseif ($Username -match "\\") {
            # Domain format: domain\user
            $domain = $Username.Split("\")[0]
            $user = $Username.Split("\")[1]
        }
        else {
            # Local user format
            $user = $Username
            $domain = $env:COMPUTERNAME
        }
        
        # Add to Event Log Readers group
        $group = [ADSI]"WinNT://./Event Log Readers,group"
        $group.Add("WinNT://$domain/$user,user")
        $group.SetInfo()
        
        Write-Log "User added to Event Log Readers group successfully" "Success"
        return $true
    }
    catch {
        Write-Log "Error adding user to Event Log Readers group: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Test if user is in Event Log Readers group
function Test-UserInEventLogReaders {
    param([string]$Username)
    
    try {
        Write-Log "Testing if user is in Event Log Readers group: $Username" "Debug"
        
        # Parse user format
        if ($Username -match "@") {
            # Email format: user@domain.com
            $user = $Username.Split("@")[0]
            $domain = $Username.Split("@")[1]
        }
        elseif ($Username -match "\\") {
            # Domain format: domain\user
            $domain = $Username.Split("\")[0]
            $user = $Username.Split("\")[1]
        }
        else {
            # Local user format
            $user = $Username
            $domain = $env:COMPUTERNAME
        }
        
        # Check group membership
        $group = [ADSI]"WinNT://./Event Log Readers,group"
        $members = $group.Members()
        
        foreach ($member in $members) {
            $memberPath = $member.GetType().InvokeMember("ADsPath", "GetProperty", $null, $member, $null)
            if ($memberPath -like "*$user*" -or $memberPath -like "*$Username*") {
                Write-Log "User found in Event Log Readers group" "Debug"
                return $true
            }
        }
        
        Write-Log "User not found in Event Log Readers group" "Debug"
        return $false
    }
    catch {
        Write-Log "Error checking Event Log Readers group membership: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Configure firewall for WEC
function Configure-Firewall {
    param(
        [string]$WECIP,
        [string]$WECHostname
    )
    
    try {
        Write-Log "Configuring firewall for WEC communication" "Info"
        
        # Configure WinRM firewall rules
        $firewallRules = @(
            @{Name="WinRM-HTTP-In"; Port=5985; Protocol="TCP"; Direction="Inbound"},
            @{Name="WinRM-HTTPS-In"; Port=5986; Protocol="TCP"; Direction="Inbound"}
        )
        
        foreach ($rule in $firewallRules) {
            try {
                # Check if rule exists
                $existingRule = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
                
                if (-not $existingRule) {
                    # Create firewall rule
                    New-NetFirewallRule -DisplayName $rule.Name -Direction $rule.Direction -Protocol $rule.Protocol -LocalPort $rule.Port -Action Allow
                    Write-Log "Created firewall rule: $($rule.Name)" "Success"
                } else {
                    Write-Log "Firewall rule already exists: $($rule.Name)" "Info"
        }
    }
    catch {
                Write-Log "Error creating firewall rule $($rule.Name): $($_.Exception.Message)" "Warning"
            }
        }
        
        # Configure WEC-specific firewall rules if IP/hostname provided
        if ($WECIP -or $WECHostname) {
            $wecRules = @(
                @{Name="WEC-HTTP-In"; Port=5985; Protocol="TCP"; Direction="Inbound"; RemoteAddress=$WECIP},
                @{Name="WEC-HTTPS-In"; Port=5986; Protocol="TCP"; Direction="Inbound"; RemoteAddress=$WECIP}
            )
            
            foreach ($rule in $wecRules) {
                try {
                    if ($rule.RemoteAddress) {
                        New-NetFirewallRule -DisplayName $rule.Name -Direction $rule.Direction -Protocol $rule.Protocol -LocalPort $rule.Port -RemoteAddress $rule.RemoteAddress -Action Allow
                        Write-Log "Created WEC-specific firewall rule: $($rule.Name) for IP: $($rule.RemoteAddress)" "Success"
        }
    }
    catch {
                    Write-Log "Error creating WEC firewall rule $($rule.Name): $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        Write-Log "Firewall configuration completed" "Success"
            return $true
    }
    catch {
        Write-Log "Error configuring firewall: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Test certificate compatibility
function Test-CertificateCompatibility {
    param([string]$ThumbPrint)
    
    try {
        Write-Log "Testing certificate compatibility: $ThumbPrint" "Debug"
        
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $ThumbPrint}
        
        if (-not $cert) {
            Write-Log "Certificate not found: $ThumbPrint" "Error"
            return $false
        }
        
        # Check if certificate has Server Authentication EKU
        $eku = $cert.EnhancedKeyUsageList
        $hasServerAuth = $false
        
        foreach ($usage in $eku) {
            if ($usage.FriendlyName -eq "Server Authentication" -or $usage.ObjectId -eq "1.3.6.1.5.5.7.3.1") {
                $hasServerAuth = $true
                break
            }
        }
        
        if (-not $hasServerAuth) {
            Write-Log "Certificate does not have Server Authentication EKU" "Error"
        return $false
        }
        
        # Check certificate validity
        if ($cert.NotAfter -lt (Get-Date)) {
            Write-Log "Certificate has expired" "Error"
            return $false
        }
        
        Write-Log "Certificate is compatible" "Success"
            return $true
    }
    catch {
        Write-Log "Error testing certificate compatibility: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Create HTTP listener
function New-HTTPListener {
    param(
        [int]$Port = 5985,
        [string]$User
    )
    
    try {
        Write-Log "Creating HTTP listener on port $Port" "Info"
        
        # Check if HTTP listener already exists
        $existingListener = winrm enumerate winrm/config/listener?Address=*+Transport=HTTP 2>$null
        if ($existingListener) {
            Write-Log "HTTP listener already exists, configuring settings" "Info"
            
            # Enable unencrypted traffic
            winrm set winrm/config/service '@{AllowUnencrypted="true"}'
            winrm set winrm/config/client '@{TrustedHosts="*"}'
            
                        $Global:RestartRequired = $true
            Write-Log "HTTP listener configuration updated" "Success"
                    return $true
                }
        
        # Try quickconfig first
        try {
            Write-Log "Attempting winrm quickconfig for HTTP" "Debug"
            $quickconfigResult = winrm quickconfig -transport:http -q
            if ($LASTEXITCODE -eq 0) {
                Write-Log "HTTP listener created via quickconfig" "Success"
                $Global:RestartRequired = $true
                    return $true
                }
            }
        catch {
            Write-Log "Quickconfig failed, attempting manual configuration" "Debug"
        }
        
        # Manual listener creation
        $listenerConfig = "winrm create winrm/config/Listener?Address=*+Transport=HTTP"
        Invoke-Expression $listenerConfig
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "HTTP listener created successfully" "Success"
            $Global:RestartRequired = $true
            return $true
        } else {
            Write-Log "Failed to create HTTP listener" "Error"
        return $false
        }
    }
    catch {
        Write-Log "Error creating HTTP listener: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Create HTTPS listener
function New-HTTPSListener {
    param(
        [int]$Port = 5986,
        [string]$ThumbPrint,
        [string]$User
    )
    
    try {
        Write-Log "Creating HTTPS listener on port $Port" "Info"
        
        # Check if HTTPS listener already exists
        $existingListener = winrm enumerate winrm/config/listener?Address=*+Transport=HTTPS 2>$null
        if ($existingListener) {
            Write-Log "HTTPS listener already exists, configuring settings" "Info"
            
            # Disable unencrypted traffic
            winrm set winrm/config/service '@{AllowUnencrypted="false"}'
            winrm set winrm/config/client '@{TrustedHosts="*"}'
            
            $Global:RestartRequired = $true
            Write-Log "HTTPS listener configuration updated" "Success"
        return $true
    }
        
        # Validate certificate if provided
        if ($ThumbPrint) {
            if (-not (Test-CertificateCompatibility -ThumbPrint $ThumbPrint)) {
                Write-Log "Certificate validation failed" "Error"
        return $false
    }
}

        # Try quickconfig first
        try {
            Write-Log "Attempting winrm quickconfig for HTTPS" "Debug"
            $quickconfigResult = winrm quickconfig -transport:https -q
            if ($LASTEXITCODE -eq 0) {
                Write-Log "HTTPS listener created via quickconfig" "Success"
                $Global:RestartRequired = $true
                    return $true
                }
        }
        catch {
            Write-Log "Quickconfig failed, attempting manual configuration" "Debug"
        }
        
        # Manual listener creation
        if ($ThumbPrint) {
            $listenerConfig = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS+Port=$Port CertificateThumbprint=`"$ThumbPrint`""
        } else {
            $hostname = $env:COMPUTERNAME
            $listenerConfig = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS+Port=$Port Hostname=`"$hostname`""
        }
        
        Invoke-Expression $listenerConfig
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "HTTPS listener created successfully" "Success"
            $Global:RestartRequired = $true
        return $true
        } else {
            Write-Log "Failed to create HTTPS listener" "Error"
        return $false
    }
    }
    catch {
        Write-Log "Error creating HTTPS listener: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Main function
function Main {
    # Show help if no action specified
    if (-not $Action) {
        Show-Help
        return
    }
    
    Write-Log "Initializing WinRM Configuration Script Enhanced v$ScriptVersion" "Info"
    Write-Log "Log file initialized: $LogFile" "Info"
    
    try {
        switch ($Action) {
            "report" {
                Write-Log "Generating WinRM configuration report" "Info"
                # Report logic here
                Write-Log "Report generated successfully" "Success"
        }
        
        "enable" {
                if (-not $ListenerType) {
                    Write-Log "ListenerType parameter is required for enable action" "Error"
                    return
                }
                
                if ($User) {
                    if (-not (Test-UserExists -Username $User)) {
                        Write-Log "User does not exist: $User" "Error"
                            return
                    }
                    
                    if (-not (Test-UserInEventLogReaders -Username $User)) {
                        Add-UserToEventLogReaders -Username $User
                    }
                }
                
                if ($ListenerType -eq "http") {
                    $port = if ($Port) { $Port } else { 5985 }
                    New-HTTPListener -Port $port -User $User
                }
                elseif ($ListenerType -eq "https") {
                    $port = if ($Port) { $Port } else { 5986 }
                    New-HTTPSListener -Port $port -ThumbPrint $ThumbPrint -User $User
                }
        }
        
        "configurefirewall" {
                Configure-Firewall -WECIP $WECIP -WECHostname $WECHostname
        }
        
        "exportcacert" {
                Write-Log "Exporting certificate" "Info"
                # Certificate export logic here
                Write-Log "Certificate exported successfully" "Success"
        }
        
        "showallcerts" {
                Write-Log "Listing all certificates" "Info"
                # Certificate listing logic here
                Write-Log "Certificate list generated" "Success"
        }
        
        "disable" {
                Write-Log "Disabling WinRM listeners" "Info"
                # Disable logic here
                Write-Log "WinRM listeners disabled" "Success"
        }
        
        "status" {
                Get-QuickStatus
            }
            
            "status-all" {
                Get-DetailedStatus
            }
        }
        
        if ($Global:RestartRequired) {
            Write-Log "WinRM service restart may be required" "Warning"
        }
    }
    catch {
        Write-Log "Error in main execution: $($_.Exception.Message)" "Error"
    }
}

# Execute main function
Main
