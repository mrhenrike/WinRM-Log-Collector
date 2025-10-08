# WinRM Log Collector v2.0

## 🚀 Quick Start

### 1. Download and Run
```powershell
# Download the script
git clone https://github.com/mrhenrike/WinRM-Log-Collector.git
cd WinRM-Log-Collector

# Run as Administrator
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -User "your_user" -AuthType basic
```

### 2. Verify Configuration
```powershell
.\winrmconfig_v2.0.ps1 -Action status
```

### 3. Generate Report
```powershell
.\winrmconfig_v2.0.ps1 -Action report
```

## 📖 Complete Guide

### Prerequisites
- ✅ PowerShell 5.1 or later
- ✅ Administrative privileges
- ✅ Windows Server 2008 R2 or later

### User Format Support
The script accepts users in multiple formats:
- `domain\user` (e.g., `CONTOSO\john.doe`)
- `user@domain.com` (e.g., `john.doe@contoso.com`)
- `localuser` (e.g., `administrator`)

## 🎯 Available Actions

### 1. **report** - Generate Configuration Report
```powershell
# Basic report
.\winrmconfig_v2.0.ps1 -Action report

# Report for specific user
.\winrmconfig_v2.0.ps1 -Action report -User "domain\user"
```

### 2. **enable** - Configure WinRM Listeners
```powershell
# HTTP listener with basic authentication
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -User "domain\user" -AuthType basic

# HTTPS listener with certificate
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType https -User "domain\user" -ThumbPrint "ABC123..."

# Custom port
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -Port 5985 -User "domain\user"
```

### 3. **configurefirewall** - Configure Firewall Rules
```powershell
# Configure firewall for WEC
.\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP "192.168.1.100" -WECHostname "wec-server"
```

### 4. **exportcacert** - Export Certificate
```powershell
# Export certificate to specific path
.\winrmconfig_v2.0.ps1 -Action exportcacert -ExportCertPath "C:\temp"
```

### 5. **showallcerts** - List Compatible Certificates
```powershell
# Show all available certificates
.\winrmconfig_v2.0.ps1 -Action showallcerts
```

### 6. **disable** - Remove WinRM Listeners
```powershell
# Remove HTTP listener
.\winrmconfig_v2.0.ps1 -Action disable -ListenerType http

# Remove HTTPS listener
.\winrmconfig_v2.0.ps1 -Action disable -ListenerType https
```

### 7. **status** - Check WinRM Service Status
```powershell
# Check current status
.\winrmconfig_v2.0.ps1 -Action status
```

## 🎯 Common Scenarios

### Scenario 1: Complete WEC Setup (HTTPS + Firewall + Certificate)
```powershell
# Step 1: Configure HTTPS listener
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType https -User "wec-collector@domain.com"

# Step 2: Configure firewall
.\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP "192.168.1.100" -WECHostname "wec-server"

# Step 3: Export certificate
.\winrmconfig_v2.0.ps1 -Action exportcacert -ExportCertPath "C:\temp"
```

### Scenario 2: Development/Testing Setup (HTTP + Basic Auth)
```powershell
# Quick HTTP setup for testing
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -AuthType basic -User "testuser"
```

### Scenario 3: Troubleshooting and Verification
```powershell
# Check status
.\winrmconfig_v2.0.ps1 -Action status

# Generate detailed report
.\winrmconfig_v2.0.ps1 -Action report -User "domain\user"

# List available certificates
.\winrmconfig_v2.0.ps1 -Action showallcerts
```

## ⚙️ Parameters Reference

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `-Action` | String | Action to perform | `report`, `enable`, `configurefirewall` |
| `-ListenerType` | String | Listener type | `http`, `https` |
| `-User` | String | User account | `domain\user`, `user@domain.com` |
| `-Port` | Integer | Custom port (1-65535) | `5985`, `5986` |
| `-ThumbPrint` | String | Certificate thumbprint | `ABC123...` |
| `-ExportCertPath` | String | Export path | `C:\temp` |
| `-AuthType` | String | Authentication type | `basic`, `kerberos` |
| `-WECIP` | String | WEC IP address | `192.168.1.100` |
| `-WECHostname` | String | WEC hostname | `wec-server` |
| `-LogLevel` | String | Logging level | `Error`, `Warning`, `Info`, `Debug` |
| `-ConfigFile` | String | Configuration file | `config.json` |

## 🔍 Logging and Troubleshooting

### Log Files
- **Location**: `%TEMP%\winrmconfig_enhanced.log`
- **Levels**: Error, Warning, Info, Debug
- **Rotation**: Automatic (keeps last 10 files)

### Enable Debug Logging
```powershell
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -LogLevel Debug
```

### Common Issues and Solutions

#### Issue 1: "Script requires elevation"
**Solution**: Run PowerShell as Administrator
```powershell
# Right-click PowerShell → "Run as Administrator"
```

#### Issue 2: "Listener already exists"
**Solution**: The script automatically handles existing listeners
```powershell
# The script will configure existing listeners instead of creating new ones
```

#### Issue 3: "Certificate not found"
**Solution**: Check available certificates
```powershell
.\winrmconfig_v2.0.ps1 -Action showallcerts
```

#### Issue 4: "Firewall rule failed"
**Solution**: Check network profile
```powershell
# Ensure network profile is "Domain" or "Private"
# Public networks may block firewall rules
```

## 🧪 Connectivity Tests

### Test WinRM Connectivity
```powershell
# Test HTTP
winrm get winrm/config/listener?Address=*+Transport=HTTP

# Test HTTPS
winrm get winrm/config/listener?Address=*+Transport=HTTPS
```

### Test WEC Connectivity
```powershell
# Test from WEC server
wecutil qc /q

# Test from client
winrm identify -r:https://wec-server:5986
```

### Test Certificate
```powershell
# Check certificate validity
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*your-server*"}
```

## 📚 Complete Examples

### Example 1: Corporate WEC Setup
```powershell
# 1. Configure HTTPS listener for WEC
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType https -User "wec-collector@contoso.com"

# 2. Configure firewall for WEC server
.\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP "10.0.1.100" -WECHostname "wec-contoso"

# 3. Export certificate for WEC configuration
.\winrmconfig_v2.0.ps1 -Action exportcacert -ExportCertPath "C:\WEC\Certificates"

# 4. Verify configuration
.\winrmconfig_v2.0.ps1 -Action status
.\winrmconfig_v2.0.ps1 -Action report
```

### Example 2: Development Environment
```powershell
# 1. Quick HTTP setup for development
.\winrmconfig_v2.0.ps1 -Action enable -ListenerType http -AuthType basic -User "devuser"

# 2. Check status
.\winrmconfig_v2.0.ps1 -Action status

# 3. Generate report
.\winrmconfig_v2.0.ps1 -Action report -User "devuser"
```

### Example 3: Troubleshooting
```powershell
# 1. Check current status
.\winrmconfig_v2.0.ps1 -Action status

# 2. List available certificates
.\winrmconfig_v2.0.ps1 -Action showallcerts

# 3. Generate detailed report
.\winrmconfig_v2.0.ps1 -Action report -User "domain\user" -LogLevel Debug

# 4. Check firewall configuration
.\winrmconfig_v2.0.ps1 -Action configurefirewall -WECIP "192.168.1.100" -WECHostname "wec-server"
```

## 🛡️ Security Considerations

### HTTPS Configuration
- ✅ Use valid certificates with Server Authentication EKU
- ✅ Configure proper certificate thumbprint
- ✅ Enable HTTPS listeners for production

### Authentication
- ✅ Use Kerberos authentication for domain environments
- ✅ Use Basic authentication only for testing/development
- ✅ Configure proper user permissions

### Firewall
- ✅ Configure specific IP ranges for WEC communication
- ✅ Use private/domain network profiles
- ✅ Monitor firewall rules regularly

## 📞 Support

### Author Information
- **Author**: Andre Henrique (Uniao Geek)
- **Email**: contato@uniaogeek.com.br
- **LinkedIn/X**: [@mrhenrike](https://www.linkedin.com/in/mrhenrike)
- **Instagram**: [@uniaogeek](https://instagram.com/uniaogeek)

### Repository
- **GitHub**: [https://github.com/mrhenrike/WinRM-Log-Collector](https://github.com/mrhenrike/WinRM-Log-Collector)
- **Issues**: [Report issues here](https://github.com/mrhenrike/WinRM-Log-Collector/issues)

### Documentation
- **README (PT-BR)**: [README.md](README.md)
- **README (EN-US)**: [README_EN.md](README_EN.md)

---

## 📋 Version History

### v2.0.0 (Current)
- ✅ Consolidated all functions from original scripts
- ✅ Enhanced error handling and logging
- ✅ Added comprehensive help system
- ✅ Improved user format parsing
- ✅ Added firewall configuration
- ✅ Enhanced certificate management
- ✅ Added connectivity tests
- ✅ Complete documentation

### v1.23
- ✅ Basic firewall configuration
- ✅ Limited functionality

### v1.0
- ✅ Initial release
- ✅ Basic WinRM configuration

---

**Made with ❤️ by [Uniao Geek](https://github.com/mrhenrike)**
