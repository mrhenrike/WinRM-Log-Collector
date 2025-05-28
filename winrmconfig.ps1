#1.22 17/04/2020 fixed formatting issues


Param (
   [string] $Action,
   [String] $ListenerType,
   [String] $User,
   [String] $Port,
   [String] $ThumbPrint,
   [String] $ExportCertPath,
   [string] $AuthType
)


Process 
{

    Set-StrictMode -Version latest
	#Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

    function help
    {
		Write-Host "Usage: An action followed by one or more parameters"
		Write-Host "Example: -Action report"
		Write-Host "Example: -Action report -User [myuser@mydomain]"
		Write-Host "Example: -Action enable -ListenerType http"
		Write-Host "Example: -Action enable -ListenerType https"
		Write-Host "Example: -Action enable -ListenerType https -AuthType basic"
		Write-Host "Example: -Action enable -User myuser@mydomain"
		Write-Host "Example: -Action enable -ListenerType http -User myuser@mydomain"
		Write-Host "Example: -Action enable -ListenerType https -User myuser@mydomain."
		Write-Host "Example: -Action enable -ListenerType https -User myuser@mydomain -Port 5999"
		Write-Host "Example: -Action exportcacert"
		Write-Host "Example: -Action exportcacert -ExportCertPath c:\temp"
		Write-Host "Example: -Action exportcert -ExportCertPath c:\temp -ThumbPrint 02FAF3E291435468607857694DF5E45B68851868"
		Write-Host "Example: -Action ShowAllCerts`n"
		Write-Host "The `"report`" action outputs the state of any listeners found, if -User is specified then the user specified's right as they pertain to WinRM are reported, otherwise only the current listeners are reported. The `"report`" command makes no changes to the system.`n"
		Write-Host "Using the `"enable`" Action with -ListenerType enables a specified listener type (http or https). Note that `"-AuthType basic`" can be used to enable BASIC auth type on listener if required (cannot be a domain controller)`n"
		Write-Host "Using the `"enable`" Action with a username sets the user's rights as they pertain to WinRM i.e. Remote WMI Access and 
		Write-Host has rights to the WMI plugin which is necessary for SID lookup by the colector`n"
		Write-Host "Both listener and user changes can be carried out in one pass by adding them both to the command line i.e `"-Action enable -ListenerType http -User myuser@mydomain`".`n"
		Write-Host "A custom port for either an http or https listener may be requested using the `"-Port`" parameter.`n"
		Write-Host "The HTTPS Listener's CA certificate can be exported to a pem file using the `"exportcacert`" Action option, if no `"-ExportCertPath`" is specified then the current directory is used to write the pem file to, if no thumbprint is specified then `"issuer`" of the current HTTPS listener is used to find the CA cert otherwise if no CA cert is located then a list of CA certs is display, the thumbprint from a viable CA cert may be copied and passed on the command line using the -Thumbprint option.`n" 
		Write-Host "The resulting PEM file can be imported into the log collector via the `"Config`" panels `"settings`" tab, clicking on `"certificates`".`n"
    }


    function recommend
	{ 
		param([string]$issue)

		switch($issue)
		{
			NO_LISTENERS { log "Recommendation: re-running this script with -Action enable and -ListenerType http or -ListenerType https to create a Listener`n" "warning"}
			USER_NOT_IN_EVENT_LOG_READERS { log "Recommendation: re-run the script with `"-Action enable`" and `"-User $user`" to correct this`n" "warning"}
			USER_NOT_WMI_PLUGIN_ENABLED { log "Recommendation: re-run the script with `"-Action enable`" and `"-User $user`" to correct this`n" "warning"}
			USER_NOT_WMI_REMOTE_ENABLED { log "Recommendation: re-run the script with `"-Action enable`" and `"-User $user`" to correct this`n" "warning"}
			NETWORK_SERVICE_NO_ACCESS_TO_SECURITY_LOGS {log "Recommendation: re-run -Action enable and -ListenerType http or -ListenerType https`n" "warning"}
			HTTP_NO_ALLOW_ENENCRYPTED { log "Recommendation: please re-run script with `"-Action enable -ListenerType http`n" "warning"}
			default {log "Unknown error code" "error"}

		}
	}


    function restartWinRM
    {
		log "Changes have been made that require a WinRM Service restart, restarting... " "warning"
		Restart-Service WinRM
		log "WinRM Service restarted." "warning"
    }

    function get-RegistryValue($key, $val) 
    {    
		(Get-ItemProperty -Path $key).$val
    }

	function set-RegistryValueDWORD($path, $key, $value) 
    {    
		Set-ItemProperty -Force -Path $path -Name $key -Value $value -Type DWord
    }

    function set-RegistryValue($path, $key, $value) 
    {    
		Set-ItemProperty -Force -Path $path -Name $key -Value $value
    }

    function getWinRMServiceStatus
    {
		(Get-Service | Where-Object {$_.name -eq "WinRM"}).status
    }

    function getFirewallServiceStatus
    {
		(Get-Service | Where-Object {$_.name -eq "MpsSvc"}).status
    }

    function startWinRMService
    {
		log "Starting WinRM service"
		Start-Service "WinRM"
    }

    function startFirewallService
    {
		log "Starting Firewall service"
		Sart-Service "MpsSvc"
    }

	
	Function startProcess
	{
		param( 	
				[string] $command,
				[string] $args,
				[Ref] $stdout,
				[Ref] $stderr
			)

		$pinfo = New-Object System.Diagnostics.ProcessStartInfo
		$pinfo.FileName = $command
		$pinfo.RedirectStandardError = $true
		$pinfo.RedirectStandardOutput = $true
		$pinfo.UseShellExecute = $false
		$pinfo.Arguments = $args
		$p = New-Object System.Diagnostics.Process
		$p.StartInfo = $pinfo
		$p.Start() | Out-Null
		$p.WaitForExit()
		[pscustomobject]@{
			stdout = $p.StandardOutput.ReadToEnd()
			stderr = $p.StandardError.ReadToEnd()
			ExitCode = $p.ExitCode  
		}
	}

	function getCACertListenerCert
	{	
		param(
			[string] $issuer
		)

		$now = (Get-Date)
		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
		$store.Open("ReadOnly")

		$currNotAfter = $now

		foreach($cert in $store.Certificates)
		{
			if($cert.NotAfter -gt $now -and $cert.Subject -eq $issuer -and $cert.Subject -eq $cert.Issuer)
			{
				$out = "CA cert Thumbprint: " + $cert.Thumbprint + " Subject: " + $cert.Subject + "  Expires: "  + $cert.NotAfter
				log $out
				$cert.Thumbprint
				break
			}
		}

    		$store.Close()    

	}

	function showAllCACerts
	{
		$bestCertPrint = ""
		$bestCertSubject = ""
		log "`nTHE FOLLOWING ARE THE INSTALLED ROOT CERTIFICATE(S)" "highlight"
		$now = (Get-Date)
		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
		$store.Open("ReadOnly")

		$currNotAfter = $now

		foreach($cert in $store.Certificates)
		{
			if($cert.NotAfter -gt $now -and $cert.Issuer -eq $cert.Subject)
			{
				$out = "Thumbprint: " + $cert.Thumbprint + " Subject: " + $cert.Subject + "  Expires: "  + $cert.NotAfter
				log $out
			}
		}

		LOG "END OF CERTIFICATE LOOKUP`n" "highlight"
    		$store.Close()    
	}


	function exportWinRMCert
	{
		
		$certs = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.thumbprint -match $ThumbPrint}

		if($certs -eq $null)
		{
			$certs = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.thumbprint -match $ThumbPrint}
			if($certs -eq $null)
			{
			    log "could not find WINRM HTTPS Listener cert with thumbprint $ThumbPrint" "error"
			    return
			}
		}

		try
		{
			foreach($cert in $certs)
			{
			    $fqdn = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
			    $tb = $cert.thumbprint
 
   			    $out = New-Object String[] -ArgumentList 3
			    $OutputFile = "$ExportCertPath\$fqdn-CA-$tb.pem"
			 
			    $out[0] = "-----BEGIN CERTIFICATE-----"
			    $out[1] = [System.Convert]::ToBase64String($cert.RawData, "InsertLineBreaks")
			    $out[2] = "-----END CERTIFICATE-----"
	 
			    [System.IO.File]::WriteAllLines($OutputFile,$out)
			    log "Exported CA Cert to $OutputFile" "highlight"
			}
		}
		catch
		{
			log "Failed to export WINRM HTTPS Listener cert $_" "error"
		}
	}
	
    function checkListeners
    { 
		param(
				$show
			)

		$cmd = "winrm e winrm/config/listener"
		[string]$execOutput = cmd /c $cmd 2`>`&1
		
		if($show -eq $true)
		{
			log "`nCURRENT LISTENER(S) INFORMATION:`n" "highlight"
		}

		if($execOutput -ne $null -and $execOutput -ne "" -and $execOutput.IndexOf("Listener") -ne -1)
		{
			#$outLines = $execOutput.Replace("`r","")
			$outLinesF = $execOutput -Split("Listener")
			$foundTransport = $false

			$global:httpsPortConfigured = ""
			$global:httpPortConfigured = ""
			
			foreach($line in $outLinesF)
			{
				if($line -ne $null -and $line -ne "")
				{
					if($show -eq $true)
					{
						log "Listener: $line `r`n"
					}
				}

				$nIndex = $line.IndexOf("Transport")
				
				if($nIndex -gt -1)
				{
				   $nIndex += 12

				   $listenerMode = $line.SubString($nIndex)

				   if($listenerMode.StartsWith("HTTPS"))
				   {
						if($global:currMode -eq "HTTP")
						{
							$global:currMode = "BOTH"
						}
						else
						{
							$global:currMode = "HTTPS"
						}
					}

					if($listenerMode.StartsWith("HTTP "))
					{
						if($global:currMode -eq "HTTPS")
						{
							$global:currMode = "BOTH"
						}
						else
						{
							$global:currMode = "HTTP"
						}
				   }

				}

				$nIndex = $line.IndexOf("CertificateThumbprint")

				if($nIndex -gt -1)
				{
				   $nIndex1 = $line.IndexOf("ListeningOn");
					if($nIndex1 -ne -1 -and $nIndex1 -gt 24)
					{
						$nIndex += 24
						$global:CertThumbPrint = $line.SubString($nIndex, $nIndex1 - $nIndex - 1).replace(" ","")
					}
				}
				
				$nIndex = $line.IndexOf("Port")
			
				if($nIndex -gt -1)
				{
				   $nIndex += 7

				   $portString = $line.SubString($nIndex)
				   $Pieces = $portString.Split()
					   
				   if($listenerMode.StartsWith("HTTPS"))
				   {
						$global:httpsPortConfigured = $pieces[0].Trim()
				   }
				   elseif($listenerMode.StartsWith("HTTP "))
				   {
						$global:httpPortConfigured = $pieces[0].Trim()
				   }

				}

			}
			
			if($show -eq $true -and $global:currMode -eq "NONE")
			{
				log "No Listeners were found!" "error"
				recommend NO_LISTENERS
			}	
		}
		else
		{
			if($show -eq $true)
			{
				log "No Listeners were found!" "error"
			    recommend NO_LISTENERS
			}
		}
    }

	function checkForRemappedSpn
    { 
		param(
				$show
			)

		$hname = (Get-WmiObject win32_computersystem).DNSHostName
		$hostEntry= [System.Net.Dns]::GetHostByName($hname)
		$ip = $hostEntry.AddressList[0].IPAddressToString
		$dmn = (Get-WmiObject win32_computersystem).Domain
		$fqdn = $hname+"."+$dmn
		$httpSpn = "HTTP/"+$fqdn
		$alternateDNS = $hname+"-sa."+$dmn
		$alternateSPN = "HTTP/"+$alternateDNS
		$cmd = "setspn -Q "+$httpSpn 
		[string]$execOutput = (cmd /c $cmd 2`>`&1) -join "`n"
		
		if($execOutput -ne $null -and $execOutput -ne "")
		{
			$outLines = $execOutput -Split("`n")
			if($outLines -gt 1)
			{
				$spnEntry = $outLines[1]
				$pieces = $spnEntry -Split(',')
				if($pieces -gt 1)
				{
					$dn = $pieces[0]
					$cn = $dn -Split('=')
					if($cn.count -gt 1)
					{
						$obj = $cn[1]
						if($obj -notmatch $hname)
						{
							log "The HTTP spn for this system has been mapped to [ $spnEntry ] which is a different object/user in Active Directory than this system and may conflict with acquiring a service ticket (ST) for this system" "warning"
							log "Since this mapping was most likely carried out to allow a service account access to the system then deleting the mapping could break an application." "warning"
							log "A workaround would be to add an alias for the system into /etc/hosts on the logcollector i.e. append a unique string to the hostname portion of the fqdn (-sa in this example)" "warning"
							log "$ip $alternateDNS" "good"
							log "or add the alternate name above to DNS so that it resolves to $ip (make sure $ip is the ip of the system that resolves at the collector if is system has multiple nics)" "warning"
							log "Next add this new unique spn to Active directory and map it ot the system as follows:" "warning"
							log "setspn -A $alternateSPN $hname" "good"
							log "finally add the event source to the collector using the new dns alias as the hostname ($alternateDNS)" "warning"
							
							return
						}
					}
				}
			}
			
			log "`nNo conflicting SPN was found matching the spn ($httpSpn) the collector requires to get a service ticket to collect`n" "good"

		}
	}
	
    function log
	{ 
			param(
					[string] $message,
					[string] $type
				)

		if($type -eq $null -or $type -eq "")
		{
		   Write-Host $message
		   logToDisk  $message
		}
		elseif($type -eq "good")
		{
		   Write-Host $message -foregroundcolor green
		   logToDisk  $message
		}
		elseif ($type -eq "warning")
		{
		  Write-Host $message -foregroundcolor yellow
		  logToDisk  "WARNING:  $message"
		}
		elseif ($type -eq "highlight")
		{
		  Write-Host $message -foregroundcolor cyan
		  logToDisk  $message
		}
		elseif ($type -eq "error")
		{
		  Write-Host $message -foregroundcolor red
		  logToDisk "ERROR:  $message"
		}
		elseif ($type -eq "heading")
		{
		  Write-Host $message -foregroundcolor blue
		  logToDisk "ERROR:  $message"
		}

    }

    function resetWinRMPluginState
    {
		log "Resetting WinRM plugin state"
		Start-Process winrm -ArgumentList "invoke Restore http://schemas.microsoft.com/wbem/wsman/1/config/plugin @{}"
    }

    function configureSecurityChannel
    {
		$sddl = ""

		if($global:reportMode -eq $true)
		{
			log "SECURITY LOG ACCESS FOR NETWORK SERVICE ACCOUNT CHECK BEGINS(WINRM SERVICE USES THIS ACCOUNT TO READ EVENT LOGS)" "highlight"
		}
		else
		{
			log "`nConfiguring security event log access for the NETWORK SERVICE accout (WinRM Service uses this account to read event logs)" "highlight"
		}

		[string]$execOutput = wevtutil gl security

		$secAccess = $execOutput.IndexOf("channelAccess")

		log "Current security acl string is: " + $execOutput 

		if($secAccess -gt 0)
                {
		   $secAccess += 15
		   $secLogging = $execOutput.IndexOf("logging")
		   if($secLogging -gt 0)
           {
			$sddl = $execOutput.SubString($secAccess, $secLogging - $secAccess-1)
			$foundChannel = $false
		   }
		}

		if($sddl -notmatch "A;;0x1;;;S-1-5-20")
		{
			if($global:reportMode -ne $true)
			{
				$sddl += "(A;;0x1;;;S-1-5-20)"
				$setChannelStringArgs = "sl security /ca:" + $sddl
				log $setChannelStringArgs 
				log "Setting security string to" + $setChannelStringArgs
				Start-Process wevtutil -ArgumentList $setChannelStringArgs -wait -NoNewWindow
			}
			else
			{
				log "Network Service SID is not added to the Security Channel ACL (Security Analytics cannot currently collect Security Event logs using the $User account)" "error"
				recommend NETWORK_SERVICE_NO_ACCESS_TO_SECURITY_LOGS
			}
		}
		else
		{
			log "Network Service SID is already added to the Security Channel ACL (Security Analytics can collect Security Event logs using the $User account)" "good"
		}



		log "SECURITY LOG ACCESS FOR NETWORK SERVICE ACCOUNT CHECK ENDS" "highlight"

	}

    function setWmiSDDL
    {
		param(
				[string] $sid
			)
			
		log "Checking access to the WinRM WMI Plugin (necessary for SID resolution)" "highlight"
        $configXml = get-RegistryValue "HKLM:Software\Microsoft\Windows\CurrentVersion\WSMAN\Plugin\WMI Provider" ConfigXML
		$configXml = $configXml -replace "`"Subscribe`"SupportsFiltering=`"true`"", "`"Subscribe`" SupportsFiltering=`"true`"" #fix for bad XML formatting

        logToDisk "Winrm WMI plugin SDDL:`n $configXml"
		
		$doc =  [xml]$configXml
		
		if($doc -eq $null)
		{
			log "No WMI Plugin config found in ConfigXML key, WinRM may have been reset!!!" "error"
			return
		}

		
        $resources = $doc.PlugInConfiguration.Resources.Resource

		foreach($resource in $resources)
		{
			if($resource.ResourceUri -match "http://schemas.microsoft.com/wbem/wsman/1/wmi")
			{
				try
				{
					$securityNode = $resource.Security
				}
				catch
				{
					if( $_ -match "cannot be found")
					{
						$securityNode = $doc.CreateElement('Security', $doc.DocumentElement.NamespaceURI)
						$resource.InsertAfter($securityNode, $null)

						$xmlAttNS = $doc.CreateAttribute("xmlns")
						$xmlAttNS.Value = $doc.DocumentElement.NamespaceURI
						$securityNode.Attributes.Append($xmlAttNS)

						$xmlAttURI = $doc.CreateAttribute("Uri")
						$xmlAttURI.Value = "http://schemas.microsoft.com/wbem/wsman/1/wmi"
						$securityNode.Attributes.Append($xmlAttURI)


						$xmlAttMatch = $doc.CreateAttribute("ExactMatch")
						$xmlAttMatch.Value = "false"
						$securityNode.Attributes.Append($xmlAttMatch)

						$xmlAttSddl = $doc.CreateAttribute("Sddl")
						$xmlAttSddl.Value = "O:NSG:BAD:P(A;;GA;;;BA)(A;;GA;;;IU)S:P(AU;FA;GA;;;WD)(AU;SA;GWGX;;;WD)"
						$securityNode.Attributes.Append($xmlAttSddl)
					}

				}
			}		
		}

        $sddl = $securityNode.Sddl

		if($sddl -eq $null)
		{
			log "No WMI Plugin config SDDL was found!!!" "error"
			return
		}

        logToDisk "setWmiSDDL looking for SID: $sid"
        logToDisk "setWmiSDDL SDDL: $sddl"

		if ($sddl -notmatch $sid)
        {
			if($global:reportMode -eq $false)
			{
				log "User: $User with SID: $sid is not part of the WinRM WMI Plugin (SID resolution would not be possible using this account) so adding to SDDL..." "warning"
				$pieces = $sddl -Split("S:P")
				$newSDDL = $pieces[0].Trim() + '(A;;GR;;;'+$sid+')S:P' + $pieces[1] 
				logToDisk "Writing new WMI Plugin SDDL: `n $newSDDL"
				$securityNode.Sddl = $newSDDL
				set-RegistryValue "HKLM:Software\Microsoft\Windows\CurrentVersion\WSMAN\Plugin\WMI Provider" ConfigXML $doc.OuterXml
				$global:restartWinRMrequired = $true
				log "Created new WMI Plugin SDDL with $User's SID" "good"
			}
			else
			{
				log "User: $User with SID: $sid is not part of the WinRM WMI Plugin (SID resolution would not be possible using this account)" "warning"
				recommend USER_NOT_WMI_REMOTE_ENABLED
			}
		}
		else
		{
			log "User $User with SID $sid is already `nadded to the WinRM WMI Plugin SDDL (Security analytics can resolve SIDs with this account)`n" "good"
		}
	
		#Example: O:NSG:BAD:P(A;;GA;;;BA)(A;;GXGR;;;S-1-5-21-4205194981-1966238051-3092141446-72291)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)
    }

    function enableCIMSecurity
	{
		param(
				[string]$sid
			)

        $WBEM_ENABLE            = 1
        $WBEM_REMOTE_ACCESS    = 0x20
		$foundInList = $false
    	$namespace = "root/cimv2"
    	$rparams = @{ComputerName="."}

		log "Checking access to the CIM Root (necessary for Event log collection)" "highlight"
		logToDisk "Checking access to the CIM Root for SID $sid"
    	$invokeparams = @{Namespace=$namespace;Path="__systemsecurity=@"} + $rparams

		logToDisk "Setup call to GetSecurityDescriptor, parameters:"

#        foreach($item in $invokeparams.GetEnumerator()) {logToDisk "$item.Key.Value $item.Value.Value"}
#		$invokeparams.GetEnumerator() | Sort-Object Value -descending

    	$output = Invoke-WmiMethod @invokeparams -Name GetSecurityDescriptor

    	$output = Invoke-WmiMethod @invokeparams -Name GetSecurityDescriptor

		if ($output.ReturnValue -ne 0)
    	{
            log "GetSecurityDescriptor failed: $($output.ReturnValue)" "error"
    	}	

        $acl = $output.Descriptor

		if($acl -ne $null)
		{   
			logToDisk "Got acl"	
		}
		else
		{
			log "Failed to get Cim namespace acl !!!" "error"
		}

		$arrDACL = $acl.DACL

		foreach($currAce in $arrDACL)
		{
			if($currAce.Trustee.SidString -match $sid)
			{
				$trusteeSid = [string]$currAce.Trustee.SidString
				logToDisk "Found trustee SID: $trusteeSid`n "
				$foundInList = $true
				break
			}
			else
			{
				$trusteeSid = [string]$currAce.Trustee.SidString
			}
		}

		if($foundInList -eq $true)
		{
			log "User $user with SID: $sid is already enabled `nfor WMI access via WinRM (Security Analytics can collect Event logs using this account)`n" "good"
			return
		}

		if($global:reportMode -eq $true)
		{
			log "User $user with SID: $sid is not enabled `nfor remote WMI access via WinRM (Security Analytics cannot collect Event logs using this account)" "error"
			recommend USER_NOT_WMI_REMOTE_ENABLED
			return
		}

		log "Enabling CIM access for user: $User with SID: $sid" "warning"
		
        $ace = (New-Object System.Management.ManagementClass("win32_Ace")).CreateInstance()
        $ace.AccessMask = $WBEM_ENABLE + $WBEM_REMOTE_ACCESS
        $ace.AceFlags = 0
        $trustee = (New-Object System.Management.ManagementClass("win32_Trustee")).CreateInstance()
        $trustee.SidString = $sid
        $ace.Trustee = $trustee
        $ace.AceType = 0x0
        $acl.DACL += $ace.psobject.immediateBaseObject
    	$setparams = @{Name="SetSecurityDescriptor";ArgumentList=$acl.psobject.immediateBaseObject} + $invokeParams

		#logToDisk "SetSecurityDescriptor parameters:"
#		$setparams.GetEnumerator() | Sort-Object Value -descending

        $output = Invoke-WmiMethod @setparams

		logToDisk "enableCIMSecurity Done"
  
        if ($output.ReturnValue -ne 0)
        {
            log "SetSecurityDescriptor failed: $output.ReturnValue (Security Analytics may not be able to collect form this device)"
        }
		else
		{
			log "Enabled CIM access for user: $User with SID: $sid" "good"
		}
    }

    function deleteListenerByPort
    { 
		param(
				[string] $port
			)

        if($global:httpsPortConfigured -eq $port)
        {
			deleteHTTPSListener	
        }
 
        if($global:httpsPortConfigured -eq $port)
        {
			deleteHTTPListener	
        }

		checkListeners $false
    }

    function deleteHTTPSListener
    {		
		log "Attempting to delete the existing HTTPS Listener on port $httpsPortConfigured" "highlight"
		$p = Start-Process winrm -ArgumentList "delete winrm/config/Listener?Address=*+Transport=HTTPS" -wait -NoNewWindow -PassThru
		checkListeners $false  #refresh our view of current listeners if any
    }

    function deleteHTTPListener
    {
		log "Attempting to delete the existing HTTP Listener on port $httpPortConfigured" "highlight"

		$p = Start-Process winrm -ArgumentList "delete winrm/config/Listener?Address=*+Transport=HTTP" -wait -NoNewWindow -PassThru
		log "command completed with return code" + $p.ExitCode
		checkListeners $false  #refresh our view of current listeners if any	
    }


    function manualConfigHTTP
    { 
		param(
				[string] $port
			) 

		log "HTTPS Port $global:httpsPortConfigured"

		if ($port -eq $null -or $port -eq "") 
		{
			$selectedPort = "5985"
		}
		else
		{
			$selectedPort = $port
		}

		$fqdn = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain

		log "Creating new WinRM HTTP Listener with port $selectedPort on $fqdn" "highlight"
		[string]$test = "winrm create winrm/config/listener?Address=*+Transport=HTTP @{Port=`"$selectedPort`";Hostname=`"$fqdn`"}"
		logToDisk $test
		$output = cmd /c $test 2`>`&1
		
		if($output -match "ResourceCreated")
		{
		   log "HTTP listener created successfully on port $selectedPort" "good"
		}
		else
		{
			log "$output" "error" 
		}

		addAllowUnencrypted
    }

    function manualConfigHTTPS
    { param(
			[string] $bestCertThumbprint,
			[string] $cn,
			[string] $port
			) 

		if ($port -eq $null -or $port -eq "") 
		{
			$selectedPort = "5986"
		}
		else
		{
			$selectedPort = $port
		}

		$fqdn = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain

		if($bestCertThumbprint -eq $null -or $bestCertThumbprint -eq "")
		{
			log "No certificate that is not expired and supports Server Authentication was found, a suitable certificate will need to be installed" "error"
			return
		}

		log "Creating HTTPS Listener with: thumbprint $bestCertThumbprint Port $selectedPort FQDN $fqdn" "highlight"
		[string]$test = "winrm `create winrm/config/listener?Address=*+Transport=HTTPS @{Port=`"$selectedPort`";CertificateThumbprint=`"$bestCertThumbprint`";" + 'Hostname=' + "`"$fqdn`"}"
		logToDisk $test
		$output = cmd /c $test 2`>`&1

		if($output -match "ResourceCreated")
		{
		   log "HTTPS listener created successfully on port $selectedPort" "good"
		}
		else
		{
			log "$output" "error" 
		}

		removeAllowUnencrypted
    }

    function quickconfigHTTPS
    { 
		log "Quick configure for HTTPS"
		winrm quickconfig -transport:https -q

		removeAllowUnencrypted
    }

    function enableBasicAuth
    {	
		log "`nBasic auth selected, enabling Basic auth for Listener" "highlight"
		$p = Start-Process winrm -ArgumentList "set winrm/config/service/auth @{Basic=`"true`"}" -wait -NoNewWindow -PassThru
    }
	
    function quickconfigHTTP
    {
		log "Quick configure for HTTP"
		winrm quickconfig -transport:http -q
		addAllowUnencrypted
    }

    function addAllowUnencrypted()
    {
		log "`nAdding the Allow unencrypted setting for HTTP Listener" "highlight"
        Set-RegistryValueDWORD "HKLM:Software\Microsoft\Windows\CurrentVersion\WSMAN\Service" allow_unencrypted 1
		$global:restartWinRMrequired = $true
	}

    function checkAllowUnencrypted()
    {
		$allowUnencrypted = 0
		log "`nSince an HTTP Listener exists then checking the Allow unencrypted setting for the HTTP Listener, which if not set would cause collection to fail." "highlight"
		
		try{
				$allowUnencrypted = get-RegistryValue "HKLM:Software\Microsoft\Windows\CurrentVersion\WSMAN\Service" allow_unencrypted
		}
		catch
		{
			logToDisk "Allow unencrypted key not found" "error"
		}
		
		$allowUnencrypted
	}
	
    function removeAllowUnencrypted()
    {
		log "Removing the Allow unencrypted setting while creating HTTPS Listener (for added Security)" "highlight"
        Set-RegistryValueDWORD "HKLM:Software\Microsoft\Windows\CurrentVersion\WSMAN\Service" allow_unencrypted 0
		$global:restartWinRMrequired = $true
    }

	function checkOSVersionFor2k8SP1
	{ 	
		$os = Get-WmiObject Win32_OperatingSystem 

		if($os.Version -match "2008SP1")
		{
			log "This version of windows is 2008 SP1 which may have issues with log truncation " "warning"
		}
		else
		{
			logToDisk "OS Version: " + $os.Version 
		}
	}

    function showAllCerts
    {
		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
		$store.Open("ReadOnly")
		log "The following certificates were found:"
		foreach($cert in $store.Certificates)
		{ 
			log "`n___________________Cert Begins_______________________________" "highlight"
			$out = "Subject: " + $cert.Subject + "`nIssuer: " + $cert.Issuer + "`nNotBefore: " + $cert.NotBefore + "`nNotAfter: " + $cert.NotAfter + "`nThumbprint: " + $cert.Thumbprint
			log $out "good"
			log "Extensions:" "warning"
			foreach($extension in $cert.Extensions)
			{
				If ($extension.Oid.FriendlyName -eq "Enhanced Key Usage")
				{
					# Get all enhanced key usages for the cert
					$enhancedKeyUsageExtension = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$extension

					foreach ($enhancedKeyUsage in $enhancedKeyUsageExtension.EnhancedKeyUsages)
					{
						$out = "Enhanced Key Usage: " + $enhancedKeyUsage.FriendlyName
						log $out "good"
					}
				}
			}
			log "Extensions ends" "warning"
			log "__________________Cert Ends____________________________________`n"
		}

    	$store.Close()    
    }


    function lookForCompatibleCerts
    {
		param(
				[ref] $bestCertPrint,
				[ref] $bestCertSubject,
				[ref] $bestIssuer
			)

		log "`nTHE FOLLOWING CERTIFICATE(S) SUPPORT SERVER AUTHENTICATION ENHANCED KEY USAGE(REQUIRED FOR CREATING AN HTTPS LISTENER):" "highlight"
		$now = (Get-Date)
		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
		$store.Open("ReadOnly")

		$currNotAfter = $now

		$fqdn = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
		logToDisk "lookForCompatibleCerts FQDN is: $fqdn" 
		foreach($cert in $store.Certificates)
		{
			if($cert.NotAfter -gt $now)
			{
				foreach($extension in $cert.Extensions)
				{	
					If ($extension.Oid.FriendlyName -eq "Enhanced Key Usage")
					{
						# Get all enhanced key usages for the cert
						$enhancedKeyUsageExtension = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$extension

						foreach ($enhancedKeyUsage in $enhancedKeyUsageExtension.EnhancedKeyUsages)
						{
							If ($enhancedKeyUsage.FriendlyName -eq "Code signing") 
							{
								log "Certificate [string]$cert.Thumbprint is a code signing cert"
							}
							
							If ($enhancedKeyUsage.FriendlyName -eq "Server Authentication") 
							{
								$certHostFromCN = getHostNameFromCertCN($cert.Subject)
								$hostname = (Get-WmiObject win32_computersystem).DNSHostName
								if($cert.Subject -match $fqdn -or $cert.Subject -eq $env:computername -or $certHostFromCN.equals($hostname, "CurrentCultureIgnoreCase"))
								{
									[string]$bestCertPrint.Value = $cert.Thumbprint
									[string]$bestCertSubject.Value = $cert.Subject
									[string]$bestIssuer.Value = $cert.Issuer
									$out = "Cert Thumbprint for valid HTTPS Listener certificate: " + $cert.Thumbprint + "  Expires: "  + $cert.NotAfter + "  Subject: " + $cert.Subject
									log $out
								}
							} 

						}
					}
				}
			}
		}

		if($bestCertThumbprint -ne "")
		{
			log "Thumbprint for most suitable cert: $bestCertThumbprint" "warning"
		}
		else
		{
			log "No Valid certificate found to allow creation of an https listener, currently this system will support http only" "warning"
		}
		LOG "END OF CERTIFICATE LOOKUP`n" "highlight"
    	$store.Close()    
   }

   	function getHostNameFromCertCN()
	{
		param(
				[string] $cn
			)
		$cnPieces = $cn -Split(',')
		
		if( $cnPieces.length -gt 0)
		{
		    if($cnPieces[0].StartsWith("cn=","CurrentCultureIgnoreCase"))
		    {
		        $cnHostPieces = $cnPieces[0] -Split('=')
			
			if($cnHostPieces.length -eq 2)
			{
		            $hostname = $cnHostPieces[1].Trim()
			    return $hostname	
			}
		    }
		}
	}
	

    function updateFirewallRule()
	{
		param(
				$port
				)

		$firewallStatus = getFirewallServiceStatus
		
		if($firewallStatus -match "Running")
		{
			log "Updating firewall rule for port $port inbound access" "highlight"
			$ruleForSA = "Security Analytics Open WinRM port for Windows 2008 and Windows 2008 R2 Servers"

			# First delete the rule if it already exists
			Start-Process netsh -ArgumentList "advfirewall firewall delete rule name=$ruleForSA"
			# Create rule
			Start-Process netsh -ArgumentList "advfirewall firewall add rule name=$ruleForSA dir=in action=allow protocol=TCP localport=port"
		}
		else
		{
			log "Skipping firewall rule for port $port inbound access as the firewall service is not running" "highlight"
		}
   }

   function logToDisk
   { 	param
		(
			[string] $message
		)

       $logMessage = (Get-Date).ToString() + " " + $message
       $logMessage | out-file -filepath $global:tmpPath\winrmconfig.log -append
    }

	#BEGIN SCRIPT
    #Import-module ActiveDirectory
    $global:tmpPath = $env:TEMP 	# for logging

	log "winrmconfig script version 1.22"
	
    $USER_NOT_VALID = 1
    $USER_NOT_IN_EVENT_LOG_READERS = 2
    $USER_NOT_WINRM_REMOTE_ENABLED = 3
    $USER_NOT_WMI_PLUGIN_ENABLED = 4
    $NETWORK_SERVICE_NO_ACCESS_TO_SECURITY_LOGS = 5
    $NO_LISTENERS = 6

    $WINRM_DEFAULT_HTTP_PORT = "5985"
    $WINRM_DEFAULT_HTTPS_PORT = "5986"
    $global:httpPort = $WINRM_DEFAULT_HTTP_PORT
    $global:httpsPort = $WINRM_DEFAULT_HTTPS_PORT
    $global:httpsPortConfigured = ""
	$global:CertThumbPrint = ""
    $global:httpPortConfigured = ""
    $global:reportMode = $true
    $global:restartWinRMrequired = $false
    $global:currMode  = "NONE"
    $bestIssuer = ""
    $doListenersOnly = $false
    $bestCertThumbprint = ""
    $bestCertDN = ""
	
    log "More verbose logging can be found in $tmpPath\winrmconfig.log" "warning"

	if($Action -eq $null -or $Action -eq "")
	{
		help
		return
	}
	elseif($Action.ToLower() -eq "exportcacert")
	{
		checkListeners $true

		if($ExportCertPath -eq "")
		{
			$ExportCertPath = Split-Path $MyInvocation.MyCommand.Path		
			log "exportcert action specified but no -ExportCertPath defaulting to current directory: $ExportCertPath" "warning"
		}
	
		if($ThumbPrint -eq "")
		{
			lookForCompatibleCerts ([ref]$bestCertThumbprint) ([ref]$bestCertDN) ([ref]$bestIssuer)
			$ThumbPrint = getCACertListenerCert $bestIssuer
		}

		if($bestCertThumbprint -eq "")
		{
			log "Cannot locate suitable WinRM HTTPS certificate, exiting..." "error"
		}

		if($ExportCertPath -ne "" -and $ThumbPrint -ne "")
		{
			exportWinRMCert 
		}
		else
		{
			log "Cert export skipped -ThumbPrint is empty and cannot be determined please pick the corect CA cert thumprint from the following entries and re-run script: " "warning"
			showAllCACerts
		}
		
		return
	}
    elseif($Action.ToLower() -eq "showallcerts")
	{
		ShowAllCerts
		return
	}
	elseif($Action.ToLower() -eq "enable")
    {
        $global:reportMode = $false
    }
	elseif($Action.ToLower() -eq "report")
    {
        $global:reportMode = $true
    }
	else
	{
		log "Invalid action specified:  $Action" "error"
		help
		return
	}
	
    $remoteparams = @{ComputerName="."}
    $computerName = (Get-WmiObject @remoteparams Win32_ComputerSystem).Name
    $lType = ""   

	
    if($User -eq $null -or $User -eq "")
    {
    	log "No user specified reporting on WinRM listener(s) only"
        $doListenersOnly = $true
    }

    $winRMStatus = getWinRMServiceStatus

    if($winRMStatus -ne "Running")
    {
		startWinRMService
    }

    if($ListenerType -ne $null -and $ListenerType -ne "")
    {
		$lType = $ListenerType.ToLower()

		if($Port -ne $null -and $Port -ne "")
		{
			if($lType -eq "http")
			{
				if($Port -ne "")
				{
					$global:httpPort = $Port
				}
			}
			elseif($lType -eq "https")
			{
				if($Port -ne "")
				{
					$global:httpsPort = $Port
				}
			}
			else
			{
				log "-ListenerType specified is invalid must be with http or https" "error"
				return
			}	   
		}
	}
	else
	{
		$global:httpPort =  $WINRM_DEFAULT_HTTP_PORT 
		$global:httpsPort = $WINRM_DEFAULT_HTTPS_PORT
	}
	
	lookForCompatibleCerts ([ref]$bestCertThumbprint) ([ref]$bestCertDN) ([ref]$bestIssuer)
	
	checkListeners $false
	
	log "Checking HTTP SPN (required for WinRM access to this system via Kerberos) has not been assigned another Domain object"  "highlight"
	checkForRemappedSpn

	if($global:reportMode -eq $false -and $lType -ne "")
	{
		if($global:currMode -eq "BOTH")
		{
			log "`nDiscovered Listeners for both HTTP and HTTPS`n on ports $global:httpPortConfigured and $global:httpsPortConfigured`n" "good"
		}
		elseif($global:currMode -eq "HTTP")
		{
			log "`nDiscovered HTTP Listener on port $global:httpPortConfigured`n" "good"
		}
		elseif($global:currMode -eq "HTTPS")
		{
			log "`nDiscovered HTTPS Listener on port $global:httpsPortConfigured`n" "good"
		}
		if($global:currMode -eq "NONE")
		{
			log "`nNo HTTP/HTTPS Listeners found`n" "error"
		}

		if($lType -eq "https")
		{
			if($bestCertThumbprint -eq "")
			{
				log "Cannot locate suitable HTTPS certificate to create a WinRM HTTPS Listener, exiting..." "error"
				return
			}


			log "HTTPS Listener requested" "good"
			
			$firewallStatus = getFirewallServiceStatus
		
			if($global:currMode -eq "BOTH")
			{
				deleteHTTPListener  # we have an HTTPS listener, it's not so secure to keep the old HTTP one
									# also takes care of usa case where use specifies HTTPS but request same port as old listener
			}
		
			#we can quickconfig even if there is an existing port
			#if($firewallStatus -match "Running" -and $global:httpsPort -eq $WINRM_DEFAULT_HTTPS_PORT) 
			if($global:httpsPort -eq $WINRM_DEFAULT_HTTPS_PORT) 
			{
				if($global:httpsPortConfigured -ne "" -and  $global:httpsPortConfigured -ne $WINRM_DEFAULT_HTTPS_PORT)
				{
					deleteHTTPSListener  #we have a listener and its not on default port so delete before quickconfig
				}
				
				quickconfigHTTPS 
				#updateFirewallRule $global:httpsPort  
				#quickconfig only opens a firewall port for HTTP listener so we do it here if the service is running
				checkListeners $false  #refresh our view of current listeners if any
			}
			else 
			{	
				if($global:httpsPortConfigured -ne "" -and $global:httpsPort -ne $global:httpsPortConfigured) #and it's not the same port as requested then delete original
				{
					log "HTTPS Listener already configured on port $global:httpsPortConfigured which is different than selected: $global:httpsPort so deleting..." "warning"
					deleteHTTPSListener   #delete current listtener
				}

				if($global:httpPortConfigured -ne "" -and $global:httpsPort -eq $global:httpPortConfigured) #and it's not the same port as requested then delete original
				{													   
					log "HTTP Listener already configured on port $global:httpPortConfigured which is the same port as requested for new HTTPS listener so deleting..." "warning"
					deleteHTTPListener   #delete current listtener
				}
				
				#$global:httpsPortConfigured -ne "" -and 
				
				if($global:httpsPort -ne $global:httpsPortConfigured)
				{
					if($ThumbPrint -ne "")
					{
						$bestCertThumbprint = $ThumbPrint #override from command line
					}
					
					manualConfigHTTPS $bestCertThumbprint $bestCertDN $global:httpsPort  #ok now manually create an HTTPS listener
					updateFirewallRule $global:httpsPort  #quickconfig only opens a firewall port for HTTP listener so we do it here if the service is running

				}
			}					
		}
		elseif($lType -eq "http")
		{
			$firewallStatus = getFirewallServiceStatus
				
			if($firewallStatus -match "Running" -and $global:httpPort -eq $WINRM_DEFAULT_HTTP_PORT) #we can quickconfig even if there is an existing port
			{
				if($global:httpPortConfigured -ne "" -and  $global:httpPortConfigured -ne $WINRM_DEFAULT_HTTP_PORT)
				{
					deleteHTTPListener  #we have a listener and its not on default port so delete before quickconfig
				}

   			    quickconfigHTTP  #wil open a firewall port if service is running
				checkListeners $false  #refresh our view of current listeners if any
			}
			else
			{
				if($global:httpsPortConfigured -ne "" -and ($global:httpPort -eq $global:httpsPortConfigured)) #if by some bad luck theres already an HTTP listener on same
				{															

					# and it's not same port as the one we are setting
					log "HTTPS Listener already configured on port $global:httpsPortConfigured same as HTTP port request: $global:httpPort so deleting..." "warning"
					deleteHTTPSListener												

					#port then we must assume its meant to be overwritten so delete it
				}

				if($global:httpPortConfigured -ne "" -and ($global:httpPort -ne $global:httpPortConfigured)) #and it's not the same port as requested then delete original
				{															
					log "HTTP Listener already configured on port $global:httpPortConfigured which is different than selected: $global:httpPort so deleting..." "warning"
					deleteHTTPListener   #delete current HTTP listener
				}
				
				if($global:httpPort -ne $global:httpPortConfigured)
				{
					manualConfigHTTP $global:httpPort  #ok now manually create an HTTP listener
					updateFirewallRule $global:httpPort  #open a firewall port for HTTP listener
					checkListeners $false  #refresh our view of current listeners if any
				}
			}				
		}
		else
		{
			if($global:reportMode -ne $true)
			{
				log "-ListenerType specified is invalid must be with http or https" "error"
				return
			}
		}
	}
		  
	checkListeners $true #recheck in case of change

	if($global:currMode -eq "HTTP" -and $global:reportMode -eq $true)
	{
		$isAllowUnencrypted = checkAllowUnencrypted

		if($isAllowUnencrypted -eq $null -or $isAllowUnencrypted -eq "")
		{
			log "Current Listener type is http and the allowunencryped setting is false, this must be fixed" "error"
			recommend HTTP_NO_ALLOW_ENENCRYPTED
		}
	}

	if($AuthType -eq "basic")
	{
		enableBasicAuth
	}
	
	configureSecurityChannel
	
	if($doListenersOnly)
	{
		log "COMPLETED LISTENER RELATED CHECKS" "highlight"
       		if($global:restartWinRMrequired -eq $true)
        	{
			restartWinRM
        	}
		return
	}
	
    if($User -ne $null -and $User -ne "")
    {
        $domain = ""
        $accountname = ""

		if($global:reportMode -eq $true)
		{
			log "`nCOLLECTION USER RIGHTS CONFIGURATION BEGINS...`n" "highlight"
		}
		else
		{
			log "COLLECTION USER RIGHTS CHECK BEGINS HERE...`n" "highlight"
		}

		if ($User.Contains('@'))
		{
			$domainaccount = $User -Split('@')
			$domain = $env:USERDOMAIN
			$accountname = $domainaccount[0]
			logToDisk "Domain: $domain"
			logToDisk "Account: $accountname"
		} 
		else 
		{
			$domain = $computerName
			$accountname = $User
			logToDisk "Local system name: $domain"
		}
	  
		$win32account = (Get-WmiObject -Class Win32_UserAccount -Filter "Domain = '$domain' and Name = '$accountname'")
	 
		if ($win32account -eq $null) 
		{
			log "User $User was not found, cannot continue!" "error"
			return
		}

		setWmiSDDL $win32account.SID
		enableCIMSecurity $win32account.SID
		
		log "Checking user $User membership to the Event Log Readers group" "highlight"
		$foundUser = $false
		$evReaders = [adsi]("WinNT://$env:COMPUTERNAME/Event Log Readers")
		$evReaders.psbase.invoke("members") | foreach {
				$username = $_.gettype().invokemember("Name", "GetProperty", $null, $_, $null)
		
				logToDisk "Event Log Readers member: $username"
				if ($username -match $accountname)
				{
					$foundUser = $true
					log "User $User is already a member of Event Log Readers group" "good"
				}
		}		
		
		if($foundUser -eq $false)
		{
			if($reportMode -eq $false)
			{
				([ADSI]"WinNT://$computerName/Event Log Readers,group").psbase.Invoke("Add",([ADSI]"WinNT://$Domain/$accountname").path)
				log "Added user $User to the Event Log Readers group" "warning"
			}
			else
			{
				log "User $User is NOT a member of the Event Log Readers group, Security Analytics cannot collect events using this account" "error"
				recommend USER_NOT_IN_EVENT_LOG_READERS
			}
		}
		
		log "`nCOLLECTION USER RIGHTS CHECK ENDS HERE...`n" "highlight"

		}

		checkOSVersionFor2k8SP1
		
    if($global:reportMode -eq $false)
    {
        if($global:restartWinRMrequired -eq $true)
        {
			restartWinRM
        }
        else
        {
			log "`nNo WinRM changes made that require a service restart " "warning" 
        }
    }
}
