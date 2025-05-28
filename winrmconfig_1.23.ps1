#1.23 18/11/2024 fixed report and firewall rules

Param (
   [string] $Action,
   [String] $ListenerType,
   [String] $User,
   [String] $Port,
   [String] $ThumbPrint,
   [String] $ExportCertPath,
   [string] $AuthType,
   [string] $WECIP,
   [string] $WECHostname
)

Process {
    Set-StrictMode -Version latest

    # Check for administrative privileges
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if (-not $IsAdmin) {
        Write-Host "Error: This script must be run with administrative privileges." -ForegroundColor Red
        Write-Host "Please reopen the terminal as Administrator or execute this script as Administrator."
        exit 1
    }

    # Ensure the execution policy is set to bypass
    $ExecutionPolicy = Get-ExecutionPolicy -Scope Process
    if ($ExecutionPolicy -ne "Bypass") {
        Write-Host "Error: Execution policy must be set to 'Bypass' for this script." -ForegroundColor Red
        Write-Host "Run the following command before executing the script:"
        Write-Host "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force" -ForegroundColor Yellow
        exit 1
    }

    # Firewall configuration action
    if ($Action -eq "configurefirewall") {
        if (-not $WECIP -or -not $WECHostname) {
            Write-Host "Error: Both WECIP and WECHostname must be provided for firewall configuration."
            exit 1
        }
        Configure-Firewall -WECIP $WECIP -WECHostname $WECHostname
        exit 0
    }

    # Additional actions (enable, exportcert, etc.) go here...
}

function Configure-Firewall {
    param (
        [string] $WECIP,
        [string] $WECHostname
    )

    Write-Host "Configuring Windows Firewall for RPC and WinRM..."

    # Allow WinRM HTTP and HTTPS (ports 5985, 5986)
    New-NetFirewallRule -DisplayName "Allow WinRM HTTP from $WECHostname or $WECIP" `
                         -Direction Inbound `
                         -Protocol TCP `
                         -LocalPort 5985,5986 `
                         -RemoteAddress $WECIP `
                         -Action Allow `
                         -Profile Any

    # Allow RPC Endpoint Mapper (port 135)
    New-NetFirewallRule -DisplayName "Allow RPC Endpoint Mapper from $WECHostname or $WECIP" `
                         -Direction Inbound `
                         -Protocol TCP `
                         -LocalPort 135 `
                         -RemoteAddress $WECIP `
                         -Action Allow `
                         -Profile Any

    # Allow RPC Dynamic Ports (range 49152-65535)
    New-NetFirewallRule -DisplayName "Allow RPC Dynamic Ports from $WECHostname or $WECIP" `
                         -Direction Inbound `
                         -Protocol TCP `
                         -LocalPort 49152-65535 `
                         -RemoteAddress $WECIP `
                         -Action Allow `
                         -Profile Any

    Write-Host "Firewall configuration completed."
}
