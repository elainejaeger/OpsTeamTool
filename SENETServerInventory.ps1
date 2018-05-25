<#

.DESCRIPTION
 	RUN LOCALLY - This script is a get only script. It collects pertinent information on server configurations. 
	Output is to a text file on the desktop. Example file name - Server1_Info_20150706_110548.txt.
	
	When the SecurityLogs switch is used, no other data is gathered and the results are put into a CSV file. If PowerShell is not run as an administrator, the user is given a message prompting for input allowing the script to continue.
	
	If no parameters are used, then the all information is collected except for Security logs and GPResults.
	
.EXAMPLE
  	.\GetInfoOnServer.ps1
	For running the script without any extra options. 
.EXAMPLE
  	.\GetInfoOnServer.ps1 -SecurityLogs
	For getting just the security logs. It defaults to 3 days.
.EXAMPLE
  	.\GetInfoOnServer.ps1 -SecurityLogs -DaysToGoBack 7
	For getting just the security logs. It defaults to 3 days. You change the starting day by using the -DaysToGoBack switch. 1-30 days are allowed.
.EXAMPLE
  	.\GetInfoOnServer.ps1 -CollectAll
	For all the information available in this version of the script including GPResults and the Security logs.
#>
[CmdletBinding(DefaultParameterSetName='Default')]
param
(
	[Parameter(ParameterSetName='GPResults')]
	[switch]$GPResults,
	[Parameter(ParameterSetName='SecurityLogs')]
	[switch]$SecurityLogs,
	[Parameter(ParameterSetName='SecurityLogs')]
	[ValidateRange(1,30)]
	$DaysToGoBack = 3,
	[Parameter(ParameterSetName='Default')]
	[switch]$CollectAll,
	[Parameter(ParameterSetName='Default')]
	[switch]$SkipKerberosCheck
)
$DateTime = $(Get-Date -format 'yyyy_MM_dd_HHmmss')
$ComputerName = $($Env:ComputerName)
$ServiceNames = ('BITS','cshost','Dfs','DFSR','Dnscache','gpsvc','IKEEXT','MpsSvc','MsMpSvc','Netlogon','OMSDK','orunprogram','PolicyAgent','PolicyAgent','ReportServer','RpcSs','RpcSs','SamSs','SENS','TermService','TermService','W3SVC','WinRM','wuauserv')
$TokenBloat = $false
$DNSCheck = $false

## Function for printing results to the text file.
function OutFile
{
	param ( $Text, [string]$Title )
	
	$MessageLength = ("$Title $(Get-Date -format 'MM/dd/yyyy_HH:mm:ss')").length
	
	'' | Out-File $FileName -Append
	"=======================================================================================================================================" | Out-File $FileName -Append
	"============================== $Title $(Get-Date -format 'MM/dd/yyyy_HH:mm:ss') " + ('='.PadRight((103 - $MessageLength),'=')) | Out-File $FileName -Append
	"=======================================================================================================================================" | Out-File $FileName -Append
	$Text | Out-File $FileName -Append
}

## Function for getting SQL logins per instance.
function SQLLogins
{
	$SMOLoaded = $false

	if ( (Test-Path 'C:\Program Files\Microsoft SQL Server\110\SDK\Assemblies\Microsoft.SqlServer.Smo.dll') )
	{
		try
		{
			Add-Type -Path 'C:\Program Files\Microsoft SQL Server\110\SDK\Assemblies\Microsoft.SqlServer.Smo.dll' -ErrorAction Stop | Out-Null
			$SMOLoaded = $true
		}
		catch 
		{}
	}
	else
	{
		try
		{
			[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo")
			$SMOLoaded = $true
		}
		catch 
		{}
	}
	
	$SQLHash = @{}
	
	if ( $SMOLoaded )
	{
		try
		{
			$SQLInstances = (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -ErrorAction Stop).InstalledInstances
		}
		catch 
		{
			$SQLInstances = @()
		}
		
		if ( $SQLInstances.count -gt 0 )
		{
			foreach ( $I in $SQLInstances )
			{
				try
				{
					if ( $I -eq 'MSSQLSERVER' )
					{
						#$SQLLogins = (New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ErrorAction Stop).Logins.name
						$SQLLogins = (New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ErrorAction Stop).Logins
					}
					else
					{
						#$SQLLogins = (New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server "$($Env:COMPUTERNAME)\$I" -ErrorAction Stop).Logins.name
						$SQLLogins = (New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server "$($Env:COMPUTERNAME)\$I" -ErrorAction Stop).Logins
					}
					## Write header to the text file.
					#$SQLHash[$I] = $SQLLogins
					$SQLHash[$I] = $SQLLogins | Select -ExpandProperty Name
				}
				catch 
				{
					$SQLHash[$I] = "No logins were found."
				}
			}
		}
		else
		{
			$SQLHash["SQL Logins"] = "No SQL instances were found."
		}
	
	}
	else
	{
		#$SQLLogins = "SMO did not load. Probably does not have SQL installed."
		$SQLHash["SQL Logins"] = "SMO did not load. Probably does not have SQL installed."
		#OutFile -Title "SQL Logins - $I" -Text "SMO did not load. Probably does not have SQL installed."
	}
	$SQLHash
	#$server = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server
	#$server.Logins
	#$server.Logins.name

}

function SecurityLogs
{
	$BeginDate = [System.Management.ManagementDateTimeConverter]::ToDMTFDateTime((get-date).AddDays(-$DaysToGoBack))

	try
	{
		[array]$Logs = Get-WmiObject Win32_NTLogEvent -filter "(logfile='Security') AND (TimeWritten>'$BeginDate') AND (Type='Audit Failure')" -ErrorAction Stop
	}
	catch 
	{
		$Logs = @()
	}
	
	if ( $Logs.count -gt 0 )
	{
		$Array = New-Object System.Collections.ArrayList
		
		foreach ( $L in $Logs )
		{
			$LogObj = '' | Select ComputerName,Logfile,EventCode,Type,TimeGenerated,RecordNumber,SourceName,CategoryString,InsertionStrings,ID,Name,Reason
			
			$LogObj.ComputerName = $L.ComputerName
			$LogObj.Logfile = $L.Logfile
			$LogObj.EventCode = $L.EventCode
			$LogObj.Type = $L.Type
			$LogObj.RecordNumber = $L.RecordNumber
			$LogObj.SourceName = $L.SourceName
			$LogObj.CategoryString = $L.CategoryString
			
			try
			{
				$LogObj.InsertionStrings = [string]::Join(',',($L.InsertionStrings.Split(',')))
			}
			catch {}
			
			try
			{
				$LogObj.TimeGenerated = $L.ConvertToDateTime($L.TimeGenerated)
			}
			catch {}
			
			try
			{
				$Message = $L.Message -Split '[\r\n]' | Where { $_ }
			}
			catch 
			{
				$Message = $null
			}
			
			if ( $Message -ne $null )
			{
				try
				{
					############### ??????????????????????????????
					$LogObj.ID = ($Message | Where { $_ -match 'ID:' }).Split(':')[1].Trim()
				}
				catch {}
				try
				{
					$LogObj.Name = ($Message | Where { $_ -match 'Name:' }).Split(':')[1].Trim()
				}
				catch {}
				try
				{
					$LogObj.Reason = ($Message | Where { $_ -match 'Reason:' }).Split(':')[1].Trim()
				}
				catch {}
			}
			$Array.Add($LogObj) | Out-Null
		}
	}
	else
	{
		$LogObj = '' | Select ComputerName,Logfile,EventCode,Type,TimeGenerated,RecordNumber,SourceName,CategoryString,InsertionStrings,ID,Name,Reason
			
		$LogObj.ComputerName = $Env:ComputerName
		$LogObj.Logfile = 'Security'
		$LogObj.Type = "Nothing came back. May not be running as an administrator."
	}
	$Array
}

function DNSCheck
{
	param ( [string]$DNSServerSearchOrder )
	$DNSCounter = 0
	foreach ( $D in ('10.64.5.5','10.64.6.6','10.64.6.7') )
	{
		if ( @($DNSServerSearchOrder.Split(';')) -contains $D )
		{
			$DNSCounter++
		}
	}
	if ( $DNSCounter -gt 1 )
	{
		$Script:DNSCheck = $true
	}
	else
	{
		$Script:DNSCheck = $false
	}
}

function ProxyInfo
{
	$Obj = '' | Select ProxyEnabled,ProxyServer,ProxyOverride
	
	try
	{
		$Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $Env:COMPUTERNAME)
		$ProxyReg = $Reg.OpenSubkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
		if ( $ProxyReg.GetValue('ProxyEnable') -eq 1 )
		{
			#$Obj.ProxyEnabled = $ProxyReg.GetValue('ProxyEnable')
			$Obj.ProxyEnabled = $true
		}
		else
		{
			$Obj.ProxyEnabled = $false
		}
		if ( $Obj.ProxyEnabled -eq $true )
		{
			$Obj.ProxyServer = $ProxyReg.GetValue('ProxyServer')
			if ( $ProxyReg.GetValue('ProxyOverride') )
			{
				$Obj.ProxyOverride = $ProxyReg.GetValue('ProxyOverride')
			}
		}
	}
	catch 
	{
		$Obj.ProxyEnabled = $Error[0].Exception.Message
	}
	$Obj
}

function ComputerInfo
{
	$Array = @()
	try
	{
		$Bios = GWMI Win32_Bios -ErrorAction Stop
	}
	catch 
	{}
	try
	{
		$OS = GWMI Win32_OperatingSystem -ErrorAction Stop
	}
	catch 
	{}
	
	try
	{
		$CS = GWMI Win32_ComputerSystem -ErrorAction Stop
	}
	catch 
	{}

	if ( $Bios -ne $null )
	{
		$Obj = '' | Select $($Env:COMPUTERNAME),Value
		$Obj."$($Env:COMPUTERNAME)" = "SerialNumber"
		$Obj.Value = $Bios.SerialNumber
		$Array+= $Obj
	}
	
	try
	{
		$IEVersion = ((([wmiclass]"\\$($Env:COMPUTERNAME)\root\default:stdRegProv").GetStringValue(2147483650,"SOFTWARE\Microsoft\Internet Explorer","svcVersion")).sValue).Split('.')[0]
	}
	catch 
	{
		$IEVersion = $null
	}

	if ( $OS -ne $null )
	{

		$Obj = '' | Select $($Env:COMPUTERNAME),Value
		$Obj."$($Env:COMPUTERNAME)" = "Operating System"
		$Obj.Value = $OS.Caption
		$Array+= $Obj
		
		$Obj = '' | Select $($Env:COMPUTERNAME),Value
		$Obj."$($Env:COMPUTERNAME)" = "Service Pack"
		$Obj.Value = $OS.ServicePackMajorVersion
		$Array+= $Obj
		
		$Obj = '' | Select $($Env:COMPUTERNAME),Value
		$Obj."$($Env:COMPUTERNAME)" = "Last Restart"
		$Obj.Value = $OS.ConvertToDateTime($OS.LastBootUpTime)
		$Array+= $Obj
		
		$Obj = '' | Select $($Env:COMPUTERNAME),Value
		$Obj."$($Env:COMPUTERNAME)" = "Server Up Time"
		$TimeSpan = New-TimeSpan $OS.ConvertToDateTime($OS.LastBootUpTime) (Get-Date)
		$Obj.Value = "$($TimeSpan.Days) Day(s) $($TimeSpan.Hours) Hour(s) $($TimeSpan.Minutes) Minute(s)"
		$Array+= $Obj
		
		$Obj = '' | Select $($Env:COMPUTERNAME),Value
		$Obj."$($Env:COMPUTERNAME)" = "OS Version"
		$Obj.Value = $OS.Version
		$Array+= $Obj

	}
	
	if ( $CS -ne $null )
	{
		$Obj = '' | Select $($Env:COMPUTERNAME),Value
		$Obj."$($Env:COMPUTERNAME)" = "Model"
		$Obj.Value = $CS.Model
		$Array+= $Obj
		
		$Obj = '' | Select $($Env:COMPUTERNAME),Value
		$Obj."$($Env:COMPUTERNAME)" = "Domain"
		$Obj.Value = $CS.Domain
		$Array+= $Obj
	}
	
	if ( $IEVersion )
	{
		$Obj = '' | Select $($Env:COMPUTERNAME),Value
		$Obj."$($Env:COMPUTERNAME)" = "Internet Explorer Version"
		$Obj.Value = $IEVersion
		$Array+= $Obj
	}
	
	if ( $Array.count -gt 0 )
	{
		OutFile -Title "Computer Information" -Text $Array
	}
	else
	{
		OutFile -Title "Computer Information" -Text "No computer information was collected."
	}
	$OS.BuildNumber
}

function Admins
{
	try
	{
		[array]$AdminGroupMembers = (Get-WMIObject -Class Win32_Group -Filter "LocalAccount=TRUE and SID='S-1-5-32-544'" -ComputerName $ComputerName -ErrorAction Stop).GetRelated("Win32_Account","Win32_GroupUser","","","PartComponent","GroupComponent",$FALSE,$NULL)
	}
	catch
	{
		$AdminGroupMembers = @()
		$AdminGroupError = $Error[0]
	}

	# Getting all group members to make sure the necessary account is there.
	if ( $AdminGroupMembers.count -gt 0 )
	{
		$AdminGroupMembersArray = @()
		foreach ( $A in $AdminGroupMembers )
		{
			$AdminGroupObj = '' | Select Account,Domain,Name,ComputerName
			$AdminGroupObj.Domain = $A.Domain
			$AdminGroupObj.Name = $A.Name
			$AdminGroupObj.Account = $A.Caption
			$AdminGroupObj.ComputerName = $A.__Server
			$AdminGroupMembersArray+= $AdminGroupObj | Select Account,ComputerName
		}
		($AdminGroupMembersArray | Sort Account)
		#OutFile -Title "ADMINISTRATORS" -Text ($AdminGroupMembersArray | Sort Account)
	}
	else
	{
		"The administrator get came back empty. $($AdminGroupError.Exception)"
		#OutFile -Title "ADMINISTRATORS" -Text "The administrator get came back empty. $($AdminGroupError.Exception)"
	}
}

function FireWallRemotePortsTesting
{
	Write-Verbose "Getting FIREWALL PORT FILTERS."
	try
	{
		[array]$FireWallRule = Get-NetFirewallRule -ErrorAction Stop
	}
	catch 
	{
		#$Message = $Error[0].Exception 
		$Message = "NetSecuity module was not available or did not load."
	}

	if ( $FireWallRule.count -gt 0 )
	{
		$FWRArray = @()
		foreach ( $FWR in $FireWallRule )
		{
			$FWRObj = '' | Select Name,DisplayName,Enabled,Profile,Direction,DynamicTransport,Protocol,LocalPort,RemotePort,IcmpType,DynamicTarget,Action,EdgeTraversalPolicy,InstanceID,Description,ElementName,CreationClassName,DisplayGroup,RuleGroup,StatusCode
			
			$FWRObj.Name = $FWR.Name
			$FWRObj.DisplayName = $FWR.DisplayName
			$FWRObj.Enabled = $FWR.Enabled
			$FWRObj.Profile = $FWR.Profile
			$FWRObj.Direction = $FWR.Direction
			$FWRObj.DynamicTarget
			$FWRObj.Action = $FWR.Action
			$FWRObj.EdgeTraversalPolicy = $FWR.EdgeTraversalPolicy
			$FWRObj.InstanceID = $FWR.InstanceID
			$FWRObj.Description = $FWR.Description
			$FWRObj.ElementName = $FWR.ElementName
			$FWRObj.CreationClassName = $FWR.CreationClassName
			$FWRObj.DisplayGroup = $FWR.DisplayGroup
			$FWRObj.RuleGroup = $FWR.RuleGroup
			$FWRObj.StatusCode = $FWR.StatusCode
			
			try
			{
				$PortFilter = $FWR | Get-NetFirewallPortFilter -ErrorAction Stop
			}
			catch 
			{
				$PortFilter = $null
			}
			
			if ( $PortFilter -ne $null )
			{
				$FWRObj.DynamicTransport = $PortFilter.DynamicTransport
				$FWRObj.Protocol = $PortFilter.Protocol
				$FWRObj.LocalPort = $PortFilter.LocalPort
				$FWRObj.RemotePort = $PortFilter.RemotePort
				$FWRObj.IcmpType = $PortFilter.IcmpType
			}
			$FWRArray+= $FWRObj
		}
		
		if ( $FWRArray.count -gt 0 )
		{
			try
			{
				$InboundRemotePort = @($FWRArray | Where { $_.Direction -eq 'Inbound' -and $_.RemotePort -ne 'Any' } | Select @{Name="Port";Expression={[int]$_.RemotePort}} | Select -ExpandProperty Port | Sort | GU)
			}
			catch
			{
				$InboundRemotePort = @()
			}
			try
			{
				$OutboundRemotePort = @($FWRArray | Where { $_.Direction -eq 'Outbound' -and $_.RemotePort -ne 'Any' } | Select @{Name="Port";Expression={[int]$_.RemotePort}} | Select -ExpandProperty Port | Sort | GU)
			}
			catch
			{
				$OutboundRemotePort = @()
			}
			try
			{
				$InboundLocalPort = @($FWRArray | Where { $_.Direction -eq 'Inbound' -and $_.LocalPort -ne 'Any' } | Select @{Name="Port";Expression={[int]$_.LocalPort}} | Select -ExpandProperty Port | Sort | GU)
			}
			catch
			{
				$InboundLocalPort = @()
			}
			try
			{
				$OutboundLocalPort = @($FWRArray | Where { $_.Direction -eq 'Outbound' -and $_.LocalPort -ne 'Any' } | Select @{Name="Port";Expression={[int]$_.LocalPort}} | Select -ExpandProperty Port | Sort | GU)
			}
			catch
			{
				$OutboundLocalPort = @()
			}
			
			$Ports = '' | Select InboundRemotePort,OutboundRemotePort,InboundLocalPort,OutboundLocalPort,Message
			$Ports.InboundRemotePort = $InboundRemotePort
			$Ports.OutboundRemotePort = $OutboundRemotePort
			$Ports.InboundLocalPort = $InboundLocalPort
			$Ports.OutboundLocalPort = $OutboundLocalPort
		}
		else
		{
			$Ports = '' | Select InboundRemotePort,OutboundRemotePort,InboundLocalPort,OutboundLocalPort,Message
			$Ports.Message = "No firewall data came back."
		}
	}
	else
	{
		$Ports = '' | Select InboundRemotePort,OutboundRemotePort,InboundLocalPort,OutboundLocalPort,Message
		$Ports.Message = "No firewall data came back."
	}
	
	
	if ( $Message )
	{
		$Ports.Message = $Message
	}
	$Ports
}

function OSSCPolicies
{
	try
	{
		Get-GPResultantSetOfPolicy -ReportType xml -Path "$HOME\Desktop\gporesults.xml" -ErrorAction Stop | Out-Null
	}
	catch
	{
		$Output = "The RSOP get failed. $($Error[0].Exception.Message)"
	}

	if ( Test-Path "$HOME\Desktop\gporesults.xml" )
	{
		try
		{
			[xml]$Links = GC "$HOME\Desktop\gporesults.xml" -ErrorAction Stop
		}
		catch
		{
			$Links = $false
		}
		
		if ( $Links )
		{
			try
			{
				$Output = $Links.Rsop.ComputerResults.GPO | Where { $_.Name.Substring(0,4) -match 'OSSC' } | Sort Name | Select -ExpandProperty Name
			}
			catch
			{
				$Output = $Error[0].Exception.Message
			}
		}
		try
		{
			Remove-Item -LiteralPath "$HOME\Desktop\gporesults.xml" -ErrorAction Stop
		}
		catch {}
	}
	else
	{
		$Output = "File was not present."
	}

	$Output
}

function NICs
{
	try
	{
		[array]$NetAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -ErrorAction Stop | Where { $_.IPEnabled }
	}
	catch 
	{
		$NetAdapters = @()
	}
	
	if ( $NetAdapters.count -gt 0 )
	{
		$NICArray = @()
		foreach ( $N in $NetAdapters )
		{
			$Obj = '' | Select DNSHostName,Description,DHCPEnabled,DNSDomain,DNSServerSearchOrder,DNSDomainSuffixSearchOrder,IPAddress,DefaultIPGateway,IPSubnet,MACAddress,DomainDNSRegistrationEnabled,FullDNSRegistrationEnabled,ServiceName
			
			$Obj.DNSHostName = $N.DNSHostName
			$Obj.Description = $N.Description
			$Obj.DNSDomain = $N.DNSDomain
			$Obj.DHCPEnabled = $N.DHCPEnabled
			
			try
			{
				$Obj.DNSServerSearchOrder = [string]::Join(';',($N.DNSServerSearchOrder))
			}
			catch {}
			try
			{
				$Obj.DNSDomainSuffixSearchOrder = [string]::Join(';',($N.DNSDomainSuffixSearchOrder))
			}
			catch {}
			try
			{
				#$Obj.IPAddress = [string]::Join(';',($N.IPAddress))
				$Obj.IPAddress = [string]::Join(';',(@($N.IPAddress | Where { $_ -match "\d{1,3}(\.\d{1,3}){3}" })) )
			}
			catch {}
			try
			{
				#$Obj.DefaultIPGateway = [string]::Join(';',($N.DefaultIPGateway))
				$Obj.DefaultIPGateway = [string]::Join(';',(@($N.DefaultIPGateway | Where { $_ -match "\d{1,3}(\.\d{1,3}){3}" })) )
			}
			catch {}
			try
			{
				$Obj.IPSubnet = [string]::Join(';',($N.IPSubnet))
			}
			catch {}
		
			$Obj.MACAddress = $N.MACAddress
			$Obj.DomainDNSRegistrationEnabled = $N.DomainDNSRegistrationEnabled
			$Obj.FullDNSRegistrationEnabled = $N.FullDNSRegistrationEnabled
			$Obj.ServiceName = $N.ServiceName

			$NICArray+= $Obj
			#$Obj
			if ( ('',$null) -notcontains ($Obj.DNSServerSearchOrder) -and ! $DNSCheck -and ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name -eq '.GBL' )
			{
				DNSCheck -DNSServerSearchOrder ($Obj.DNSServerSearchOrder)
				Write-Verbose "Calling the DNSCheck"
			}
		}
	}

	if ( $NICArray.count -gt 0 )
	{
		$NICArray
	}
	else
	{
		$null
	}
}
function GetDiskSpace
{
    # Get the Disks for this computer
    $diskspace = New-Object System.Collections.Generic.List[System.Object]
    $diskspace.add("$env:COMPUTERNAME   Dir  Free  Total/GB")
    $diskspace.add("_______________________________________")
    $colDisks = get-wmiobject Win32_LogicalDisk -computername $env:COMPUTERNAME -Filter "DriveType = 3"
    # For each disk calculate the free space
        foreach ($disk in $colDisks) {
            $size = $disk.FreeSpace/$disk.Size
            $TotalSpace = [System.Math]::Round($disk.Size/1GB)
            If($size -gt 0){
                $PercentFree = [Math]::Round($size * 100)
            }
            $Drive = $disk.DeviceID
           $diskspace.Add("$env:COMPUTERNAME - $Drive - $PercentFree% - $TotalSpace in GB")
           
           
            
         }
         $diskspace
     

}
function GetSharesInfo
{
    $shares = gwmi -Class win32_share -ComputerName $env:COMPUTERNAME | select -ExpandProperty Name 
    $ACL = @() 
    foreach ($share in $shares) 
    { 
        $acl+= $share 
        #Write-Host $share -ForegroundColor Green 
        #Write-Host $('-' * $share.Length) -ForegroundColor Green 
        $objShareSec = Get-WMIObject -Class Win32_LogicalShareSecuritySetting -Filter "name='$Share'"  -ComputerName $env:COMPUTERNAME
        try { 
            $SD = $objShareSec.GetSecurityDescriptor().Descriptor   
            foreach($ace in $SD.DACL){  
                $UserName = $ace.Trustee.Name     
                If ($ace.Trustee.Domain -ne $Null) {$UserName = "$($ace.Trustee.Domain)\$UserName"}   
                If ($ace.Trustee.Name -eq $Null) {$UserName = $ace.Trustee.SIDString }     
                [Array]$ACL += New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ace.AccessMask, $ace.AceType) 
                } #end foreach ACE           
            } # end try 
        catch 
            { 
            $acl+= "Unable to obtain permissions for $share" 
            $acl += " "
            } 
        $ACL 
    }  

}
function KerberosTokenSizes
{
	param
	(
		$Principal = $Env:USERNAME
	)

	function GetSIDHistorySIDs
	{   
		param ([string]$objectname)
		
		try
		{
			$DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			$RootString = "LDAP://" + $DomainInfo.Name
			$Root = New-Object  System.DirectoryServices.DirectoryEntry($RootString)
			$searcher = New-Object DirectoryServices.DirectorySearcher($Root)
			$searcher.Filter = "(|(userprincipalname=$objectname)(name=$objectname))"
			$results = $searcher.findone()
		}
		catch 
		{
			$results = $null
		}
		
		if ($results -ne $null)
		{
			[array]$SIDHistoryResults = $results.properties.sidhistory
		}
		
		if ( $SIDHistoryResults.count -gt 0 )
		{
			#Clean up the SIDs so they are formatted correctly
			$SIDHistorySids = @()
			foreach ($SIDHistorySid in $SIDHistoryResults)
			{
				try
				{
					$SIDString = (New-Object System.Security.Principal.SecurityIdentifier($SIDHistorySid,0)).Value
					$SIDHistorySids += $SIDString
				}
				catch {}
			}
			if ( $SIDHistorySids.count -gt 0 )
			{
				$SIDHistorySids
			}
		}
		else
		{
			$null
		}
	}

	#Obtain domain SID for group SID comparisons.yes
	
	$AllGroupSIDHistories = @()
	$SecurityGlobalScope  = 0
	$SecurityDomainLocalScope = 0
	$SecurityUniversalInternalScope = 0
	$SecurityUniversalExternalScope = 0
	$GroupArray = New-Object System.Collections.ArrayList
	
	try
	{
		$UserIdentity = New-Object System.Security.Principal.WindowsIdentity($Principal)
		[array]$Groups = $UserIdentity.get_Groups()
		$DomainSID = $UserIdentity.User.AccountDomainSid
		#$GroupCount = $Groups.Count
	}
	catch 
	{
		$Groups = @()
	}

	if ( $Groups.count -gt 0 )
	{
		foreach ($GroupSid in $Groups) 
		{     
			$Group = [adsi]"LDAP://<SID=$GroupSid>"
			
			if ( $Group -ne $null )
			{
				$GroupType = $Group.groupType
				
				$GrObj = '' | Select sAMAccountName,Type,CN,DN,memberOf

				try
				{
					$GrObj.memberOf = [string]::Join(";",(($Group.memberOf).Split()))
				}
				catch {}
				try
				{
					$GrObj.CN = $Group.CN.ToString()
				}
				catch {}
				try
				{
					$GrObj.DN = $Group.distinguishedName.ToString()
				}
				catch {}
				try
				{
					$GrObj.sAMAccountName = $Group.sAMAccountName.ToString()
				}
				catch {}
				
				if ( $($Group.name) -ne $null)
				{
					[array]$SIDHistorySids = GetSIDHistorySIDs ($Group.name)
					
					If (($SIDHistorySids | Measure-Object).Count -gt 0) 
					{
						$AllGroupSIDHistories += $SIDHistorySids
					}
				}	  

				#Count number of security groups in different scopes.
				switch -exact ($GroupType)
				{	
					#Domain Global scope
					"-2147483646" { $SecurityGlobalScope++; $GrObj.Type = "Domain Global Group" }
					#Domain Local scope
					"-2147483644" { $SecurityDomainLocalScope++; $GrObj.Type = "Domain Local Group" }
					#Universal scope; must separate local
					#domain universal groups from others.
					"-2147483640"   
					{
						if ($GroupSid -match $DomainSID) { $SecurityUniversalInternalScope++; $GrObj.Type = "Local Universal Group" }
						else { $SecurityUniversalExternalScope++; $GrObj.Type = "External Universal Group" }
					}
					default { $GrObj.Type = 'Unknown' }
				}	
			}
			
			if ( $GrObj -ne $null )
			{
				$GroupArray.Add($GrObj) | Out-Null
			}
		}

		#Look for claims if OS supports it
		if ($BuildNo -ge 9200)
		{
			try
			{
				[array]$UserIdentity = New-Object System.Security.Principal.WindowsIdentity($Principal)
				$ClaimCounter = $UserIdentity.count
			}
			catch 
			{
				$ClaimCounter = 0
			}
		}

		#Get user object SIDHistories
		[array]$SIDHistoryResults = GetSIDHistorySIDs -objectname $Principal
		$SIDCounter = $SIDHistoryResults.count
	                
		$GroupSidHistoryCounter = $AllGroupSIDHistories.Count 
		#$AllSIDHistories = $SIDCounter + $GroupSidHistoryCounter

		#Calculate the current token size.
		#$TokenSize = 0 #Set to zero in case the script is *gasp* ran twice in the same PS.
		[int]$TokenSize = 1200 + (40 * ($SecurityDomainLocalScope + $SecurityUniversalExternalScope + $GroupSidHistoryCounter + $ClaimCounter)) + (8 * ($SecurityGlobalScope  + $SecurityUniversalInternalScope))
		[int]$DelegatedTokenSize = 2 * (1200 + (40 * ($SecurityDomainLocalScope + $SecurityUniversalExternalScope + $GroupSidHistoryCounter + $ClaimCounter)) + (8 * ($SecurityGlobalScope  + $SecurityUniversalInternalScope)))
		
		if ( $DelegatedTokenSize -ge 48000 -and $DelegatedTokenSize -lt 65535 )
		{
			$TokenMessagge = "******* Intermittent logon issues may occur from Kerberos token sizes above 48,000 *******"
			$Script:TokenBloat = $true
		}
		elseif ( $DelegatedTokenSize -ge 65535 )
		{
			$TokenMessagge = "******* Logon issues will occur from Kerberos token sizes above 65,535 *******"
			$Script:TokenBloat = $true
		}
		else
		{
			$TokenMessagge = "************************************"
		}
		
		#$Results = '' | Select TokenSize,DelegatedTokenSize
		#$Results.TokenSize = $TokenSize
		#$Results.DelegatedTokenSize = $DelegatedTokenSize
		#$Results
		"
		Kerberos Token Size: $TokenSize
		Kerberos Delegated Token Size: $DelegatedTokenSize
		$TokenMessagge
		"
	}
	else
	{
		"Kerberos checked erred."
	}
}


function GetOU
{
	$ComputerName = ($Env:ComputerName)
	$Counter = 0
	
	do
	{
		$GetComputerDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name
		$Counter++
	}
	while ( ('',$null) -notcontains $GetComputerDomain -or ('',$null) -notcontains $GetComputerDomain -and $Counter -ge 2 )

	if ( ('',$null) -notcontains $GetComputerDomain )
	{
		try
		{
			$Domain = [string]::Join(',',($GetComputerDomain.Split('.') | foreach { 'DC=' + $_ }))
		    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
			$searcher = New-Object System.DirectoryServices.DirectorySearcher($root) 
		    $searcher.Filter = "(&(objectClass=computer)(name=$ComputerName))" 
		    [System.DirectoryServices.SearchResult]$result = $searcher.FindOne() 
		}
		catch 
		{
			return $Error[0].Exception.Message
		}
	}
	else
	{
		return "No domain value was returned."
	}

	if ( ('',$null) -notcontains ($result.Properties.distinguishedname) )
	{
		try
		{
			$result.Properties.distinguishedname[0].Split(',',2)[-1]
		}
		catch
		{
			return $Error[0].Exception.Message
		}
	}
	else
	{
		$null
	}
}

function getIISinfo
{
    $webInfo = @()
	try
	{
        $webInfo = Get-WebBinding -ErrorAction SilentlyContinue | % {
            $name = $_.ItemXPath -replace '(?:.*?)name=''([^'']*)(?:.*)', '$1'
            New-Object psobject -Property @{
                Name = $name
                Protocol = $_.protocol
                Binding = $_.bindinginformation
            }
        }
	}
	catch 
    {
        $appCmd = "$Env:SystemRoot\system32\inetsrv\appcmd.exe list site"
        $webinfo = Invoke-expression -command $appCmd  -ErrorAction SilentlyContinue   
    }
    $webinfo
}
function getInstallApps
{
    $apps = $()
    $apps = Get-WmiObject -class Win32_product | select Name, Version
    $apps
}

function getRolesFeatures
{
    $rolesFeatures = @()
    try
    {
        $rolesFeatures = Get-WmiObject -class Win32_ServerFeature | Select Name, ID
    }
    catch
    {
        $rolesFeatures = "Unable to gather Windows Features on this system"
    }
    $rolesFeatures
}

function LMHOST
{
    $filename = "$($Env:SystemRoot)\System32\drivers\etc\hosts"
    [regex]$r="\S" 
    
	try
	{
		$hostsContent = Get-Content $filename | where {(($r.Match($_)).value -ne "#") -and ($_ -notmatch "^\s+$") -and ($_.Length -gt 0)}
	}
	catch 
    {
        $hostsContent = "Unable to get any hosts file content"
    }
    $hostsContent
}
	
######################################################
## This script has one or more data points that call for running this read only script as an administrator. Checking for elevation status and requesting elevation if not currently elevated as an administrator.
If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
	#"No Administrative rights, it will display a popup window asking user for Admin rights"
	Write-Host "This is a read only script."  -ForegroundColor DarkRed -BackgroundColor Yellow
	Write-Host "You are not running PowerShell as an administrator. This script has one or more data points that call for running this read only script as an administrator."  -ForegroundColor DarkRed -BackgroundColor Yellow
	Write-Host "To elevate, type Yes and press <ENTER>." -ForegroundColor DarkRed -BackgroundColor Yellow
	Write-Host "If you enter YES, a new PowerShell window will open and, based on your UAC settings, you may be prompted to approve the use of the Administrator shell."  -ForegroundColor DarkRed -BackgroundColor Yellow
	$Answer = Read-Host
	
	if ( $Answer.ToUpper() -eq 'YES' )
	{
		$Parameters = $MyInvocation.Line.Split(' ',2)[1]
		$Definition = ($MyInvocation.MyCommand.Definition)
		$arguments = "-NoProfile -NoExit $Definition $Parameters " 
		Start-Process "$psHome\powershell.exe" -Verb Runas -ArgumentList $arguments -ErrorAction 'stop'
		Exit
	}
	else
	{
		Write-Host "The script is exiting." -ForegroundColor Cyan
		Exit  Yes
	}
}

if ( $CollectAll -or $SecurityLogs )
{
	Write-Verbose "Getting the Security Event logs."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting the Security Event logs."
		
	Write-Host "Collecting the security logs for the past $DaysToGoBack day(s)..." -ForegroundColor Cyan
 
	$LogFileOutput = "$HOME\Desktop\$($Env:ComputerName)_SecurityLogs_$DateTime.csv" 
	
	$Logs = SecurityLogs
	
	if ( $Logs.count -gt 0 )
	{
		$Logs | Export-Csv $LogFileOutput -NoTypeInformation
		Write-Host "The file has been saved to the desktop.`n$LogFileOutput" -ForegroundColor Yellow
	}
	else
	{
		Write-Host "There were no log entries returned. Try running PowerShell as an administrator or try a longer time period with the DaysToGoBack parameter." -ForegroundColor Yellow
		Write-Host "The default is 3." -ForegroundColor Yellow
	}
}

if ( (Get-Module -ListAvailable | Where { $_.Name -eq 'GroupPolicy' }) -and 1 -eq 0 )
{
	If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{   
		#"No Administrative rights, it will display a popup window asking user for Admin rights"
		Write-Host "This is a READ ONLY script."  -ForegroundColor DarkRed -BackgroundColor Yellow
		Write-Host "You are NOT running PowerShell as an administrator." -ForegroundColor DarkRed -BackgroundColor Yellow
		Write-Host "This script checks for OSSC group policies that are applied to this computer which requires elevation. Type Yes and press <ENTER>." -ForegroundColor DarkRed -BackgroundColor Yellow
		Write-Host "If you enter YES, a new PowerShell window will open and, based on your UAC settings, you may be prompted to approve the use of the Administrator shell."  -ForegroundColor DarkRed -BackgroundColor Yellow
		$Answer = Read-Host
		
		if ( $Answer.ToUpper() -eq 'YES' )
		{
			$Parameters = $MyInvocation.Line.Split(' ',2)[1]
			$Definition = ($MyInvocation.MyCommand.Definition)
			$arguments = "-NoProfile -NoExit $Definition $Parameters " 
			Start-Process "$psHome\powershell.exe" -Verb Runas -ArgumentList $arguments -ErrorAction 'stop'
			Exit
		}
		else
		{
			Write-Host "Group policy information was denied by user." -ForegroundColor Yellow
			#Exit  Yes
			$GPLinks = "Group policy information was denied by user."
		}
	}
	else
	{
		Write-Verbose "RSOP"
		Write-Progress -Activity "RSOP" -Status "Getting Resultant Set of Policies."
		$GPLinks = OSSCPolicies
	}
}
else
{
	$GPLinks = "The GroupPolicy module is not available."
}

if ( $CollectAll -or ! $SecurityLogs )
{
	$ScriptName = ($MyInvocation.MyCommand.Name) + ' '

	$FileName = "$HOME\Desktop\$($Env:ComputerName)_Info_$DateTime.txt"

	"============================== $($Env:ComputerName) $(Get-Date -format 'MM/dd/yyyy_HH:mm:ss') $ScriptName" + ('='.PadRight((106 - (("($Env:ComputerName) $(Get-Date -format 'MM/dd/yyyy_HH:mm:ss') $ScriptName").length)),'=')) | Out-File $FileName -Append
	"=================================================== PowerShell Version $(($host).Version.Major) ==============================================================" | Out-File $FileName -Append
	
	## Start gathering information.
	Write-Verbose "Getting WHO AM I."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting WHO AM I."
	try
	{
		$WHOAMI = WHOAMI
	}
	catch 
	{}
		
	Write-Verbose "Getting the local computer info."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting the local computer info."
	$BuildNo = ComputerInfo
	
	Write-Verbose "Getting the local proxy info."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting the local proxy info."
	$Proxy = ProxyInfo
	
	Write-Verbose "The machines OU."
	Write-Progress -Activity " Collecting Computer's OU" -Status "Getting the machines OU."
	$GetOU = GetOU

	Write-Verbose "The machines Drive info."
	Write-Progress -Activity " Collecting Drive information" -Status "Getting the machines drive info."
    $driveInfo = GetDiskSpace

	if ( ! $SkipKerberosCheck )
	{
		Write-Verbose "Getting KERBEROS Token Sizes."
		Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting KERBEROS Token Sizes."
		$KerberosCheck = (KerberosTokenSizes -UserName ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name))
	}
		
	Write-Verbose "Getting the local administrators."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting the local administrators."
	$Administrators = Admins
	
	Write-Verbose "Getting the SQL logins."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting the SQL logins."
	$SQLLogins = SQLLogins
	
	Write-Verbose "Checking for Host file entries."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Checking for Host file entries."
	[array]$LMHosts = LMHOST
	
	Write-Verbose "Getting TCP - DYNAMIC PORT RANGE."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting TCP - DYNAMIC PORT RANGE."
	try
	{
		$DynamicPortRangeTCP = netsh interface ipv4 show dynamicportrange tcp
	}
	catch 
	{
		$DynamicPortRangeTCP = "netsh interface ipv4 show dynamicportrange tcp erred."
	}

	Write-Verbose "The machines Installed Apps."
	Write-Progress -Activity " Collecting Computer's installed applications" -Status "Getting the machines installed apps."
    $getInstallApps = getInstallApps

	Write-Verbose "The machines Features."
	Write-Progress -Activity " Collecting Computer's features" -Status "Getting the machines features."
    $getRolesFeatures = getRolesFeatures

	Write-Verbose "The machines IIS info."
	Write-Progress -Activity " Collecting Computer's IIS info" -Status "Getting the machines IIS info."
    $getIISinfo = getIISinfo

	Write-Verbose "Getting UDP - DYNAMIC PORT RANGE."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting UDP - DYNAMIC PORT RANGE."
	try
	{
		$DynamicPortRangeUDP = netsh interface ipv4 show dynamicportrange udp
	}
	catch 
	{
		$DynamicPortRangeUDP = "netsh interface ipv4 show dynamicportrange udp erred."
	}
	
	Write-Verbose "Getting GPRESULTS for group policy."
	Write-Progress -Activity " Collecting Get getting GPRESULTS for group policy" -Status "Getting GPRESULTS for group policy."
	try
	{
		$Gpresult = gpresult /r /scope:computer
	}
	catch 
	{
		$Gpresult = "gpresult /r /scope:computer erred."
	}
	
	if ( ('',$null,"gpresult /r /scope:computer erred.") -notcontains $Gpresult )
	{
		$GP_ComputerSettingsStart = ([array]::IndexOf($Gpresult,'COMPUTER SETTINGS'))
		#$GP_ComputerSettingsStop = $GP_ComputerSettingsStart + 5
		
		#$GPObjectsStart = ([array]::IndexOf($Gpresult,'    Applied Group Policy Objects'))
		$GPObjectsStop = ([array]::IndexOf($Gpresult,'    The following GPOs were not applied because they were filtered out') - 2)
		
		#$Gpresult[$GP_ComputerSettingsStart..$GPObjectsStop]
		
		$GPOsFilteredStart = ([array]::IndexOf($Gpresult,'    The following GPOs were not applied because they were filtered out'))
		$GPOsFilteredStop = ([array]::IndexOf($Gpresult,'    The computer is a part of the following security groups') - 2)
		
		#$Gpresult[$GPOsFilteredStart..$GPOsFilteredStop] | Where { $_ }
		
		$GPOsSecurityGroupsStart = ([array]::IndexOf($Gpresult,'    The computer is a part of the following security groups'))
		#$GPOsSecurityGroupsStop = $($Gpresult.count - 1)
		#$GPOsSecurityGroupsStop = ([array]::IndexOf($Gpresult,($Gpresult[$GPOsSecurityGroupsStart..-1] | Where { ('',$null) -contains $_ } | Select -First 1)))
		
		#$Gpresult[$GPOsSecurityGroupsStart..$($Gpresult.count - 1)]
		
		$GPArray = @()
		foreach ( $G1 in @($Gpresult[$GP_ComputerSettingsStart..$GPObjectsStop]) )
		{
			$GPArray+= $G1
		}
		foreach ( $G2 in @($Gpresult[$GPOsFilteredStart..$GPOsFilteredStop] | Where { $_ }) )
		{
			$GPArray+= $G2
		}
		foreach ( $G3 in @($Gpresult[$GPOsSecurityGroupsStart..$($Gpresult.count - 1)]) )
		{
			$GPArray+= $G3
		}
		
	}
	
	## Import the NetSecurity module before calling the function.
	#if ( (Get-Module -ListAvailable | Where { $_.Name -eq 'NetSecurity' }).Count -gt 0 )
	if ( (Get-Module -ListAvailable | Where { $_.Name -eq 'NetSecurity' }).Count -gt 0 -and $host.Version.Major -gt 2 )
	{
		try
		{
			Write-Verbose "Getting Fire Wall Ports."
			Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting Fire Wall Ports."
			Import-Module NetSecurity -ErrorAction Stop
			$FirewallPorts = FireWallRemotePortsTesting
		}
		catch
		{
			$FirewallPorts = '' | Select InboundRemotePort,OutboundRemotePort,InboundLocalPort,OutboundLocalPort
			$FirewallPorts.InboundRemotePort = "NetSecurity module failed to load."
		}
	}
	else
	{
		$FirewallPorts = '' | Select InboundRemotePort,OutboundRemotePort,InboundLocalPort,OutboundLocalPort
		$FirewallPorts.InboundRemotePort = "NetSecurity module was not available."
	}

	Write-Verbose "The machines Shares info."
	Write-Progress -Activity " Collecting Shares info" -Status "Getting the machines shares info."
	$SharesInfo = GetSharesInfo

	Write-Verbose "Getting Network interface information."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting Network interface information."
	try
	{
		[array]$NETInterface = NICs
	}
	catch 
	{
		$NETInterface = "Network Interfaces erred."
	}
		
	Write-Verbose "Getting IPCONFIG /ALL."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting Network interface information."
	try
	{
		$IPConfig = ipconfig /all
	}
	catch 
	{
		$IPConfig = "ipcofig erred."
	}
	
	Write-Verbose "Getting ROUTE PRINT."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting ROUTE PRINT."
	try
	{
		$RoutePrint = ROUTE PRINT
	}
	catch 
	{
		$RoutePrint = "Route Print erred."
	}	
	
	if ( $RoutePrint -ne "Route Print erred." )
	{
		$PRStart = ([array]::IndexOf($RoutePrint,'Persistent Routes:') + 1)
		$IRTStart = [array]::IndexOf($RoutePrint,'IPv6 Route Table')
		$PRStop = $IRTStart - 2

		$ARStart = ([array]::IndexOf($RoutePrint,'Active Routes:') + 2)
		$ARStop = $PRStart - 3
		#$RoutePrint = $RoutePrint.Split("`n")
		
		## Getting the expected gateway.
		$GWArray = @()
		foreach ( $R in $RoutePrint[$ARStart..$ARStop] )
		{
			$GW = ($R.Split(' ') | Where { $_ -ne '' })[2]
			if ( $GW -ne 'On-link' )
			{
				$GWArray+= $GW
			}
		}
		
		$GWArray = $GWArray | Sort | GU
		
		## Checking for gateways that do not match the expected gateway.
		if ( @($RoutePrint[$($PRStart + 1)..$PRStop] | Where { ('','None') -notcontains $_.Trim() -and $_ -notmatch '=' }).count -gt 0 )
		{
			#foreach ( $PR in $RoutePrint[$($PRStart + 1)..$PRStop] )
			foreach ( $PR in ($RoutePrint[$($PRStart + 1)..$PRStop] | Where { ('','None') -notcontains $_.Trim() -and $_ -notmatch '='}) )
			{
				if ( $GWArray -notcontains ($PR.Split(' ') | Where { $_ -ne '' -and $_ -ne 'On-link' -and $_ -notmatch '=' })[2] )
				{
					$PersistentRoutesSuspect = $true
				}
			}
		}
	}	
		
######################################################
	
	
	Write-Verbose "Getting the SERVICES."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting the SERVICES."
	try
	{
		$Services =  Get-WmiObject Win32_Service | Where { $ServiceNames -contains $_.Name -or $_.Name -match 'SQL' } | Sort Name | Select StartMode,State,Name,DisplayName    
	}
	catch 
	{
		$Services = "Service get erred."
	}
	
	Write-Verbose "Getting NETSTAT -an."
	Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting NETSTAT -an."
	try
	{
		$Netstat = netstat -an
	}
	catch 
	{
		$Netstat = "Netstat -an erred."
	}

	## GPResults. If the switch is used
	if ( $CollectAll -or $GPResultsHTML )
	{
		Write-Verbose "Getting the GPResults." 
		Write-Progress -Activity " Collecting Get Computer Information" -Status "Getting the GPResults."
		$GPResultHTMLFile = "$HOME\Desktop\$($Env:ComputerName)_GPResults_$DateTime.html" 

		try
		{
			GPRESULT /H $GPResultHTMLFile
		}
		catch
		{
			Write-Host "GPRESULT erred." -ForegroundColor DarkRed -BackgroundColor Yellow
		}
	}
	Write-Host "The file has been saved to the desktop.`n$FileName" -ForegroundColor Yellow
}

## Summary
$SummaryArray = @()
$Summary = '' | Select Title,Message
$Summary.Title = 'Collecting Document'
$Summary.Message = "Findings"
$SummaryArray+= $Summary

if ( $PersistentRoutesSuspect )
{
	$Summary = '' | Select Title,Message
	$Summary.Title = 'Persistent Routes'
	$Summary.Message = "The persistent routes contain alternative gateways."
	$SummaryArray+= $Summary
}

if ( $NETInterface -ne "Network Interfaces erred." -and ($NETInterface.count -lt 2 -and !$NETInterface[0].DHCPEnabled) -and !$DNSCheck )
{
	$Summary = '' | Select Title,Message
	$Summary.Title = 'Anycast DNS Servers'
	$Summary.Message = "The script did not find two or more Anycast DNS servers listed on the NIC that is joined to the  domain.
For more information, please refer to:
http://ipsconfigs/TEG-SOE1.1b.htm

Primary DNS
  10.64.5.5
  
Secondary DNS
  10.64.6.6
  
Tertiary DNS
  10.64.6.7
	"
	$SummaryArray+= $Summary
}

if ( $GWArray.count -gt 1 )
{
	$Summary = '' | Select Title,Message
	$Summary.Title = 'Route Print Gateways'
	$Summary.Message = "There are mutliple gateways listed in the (Active Routes:) portion of the Route Print output. This may need to be investigated."
	$SummaryArray+= $Summary
}

if ( [int]($DynamicPortRangeUDP | Where { $_ -match 'Start Port' }).Split(':')[-1].Trim() -ne 49152 -and [int]($DynamicPortRangeUDP | Where { $_ -match 'Number of Ports' }).Split(':')[-1].Trim() -ne 16384 )
{
	$Summary = '' | Select Title,Message
	$Summary.Title = 'UDP Dynamic Port Range'
	$Summary.Message = "The UDP dynamic port range does not match the design. In an elevated Cmd console or PowerShell console, run this command: --> netsh int ipv4 set dynamicport udp start=49152 num=16384 <--."
	$SummaryArray+= $Summary
}

if ( [int]($DynamicPortRangeTCP | Where { $_ -match 'Start Port' }).Split(':')[-1].Trim() -ne 49152 -and [int]($DynamicPortRangeTCP | Where { $_ -match 'Number of Ports' }).Split(':')[-1].Trim() -ne 16384 )
{
	$Summary = '' | Select Title,Message
	$Summary.Title = 'TCP Dynamic Port Range'
	$Summary.Message = "The TCP dynamic port range does not match the design. In an elevated Cmd console or PowerShell console, run this command:   netsh int ipv4 set dynamicport tcp start=49152 num=16384  "
	$SummaryArray+= $Summary
}

if ( $Services | Where { $_.Name -eq 'MpsSvc' -and $_.State -ne 'Running' } )
{
	$Summary = '' | Select Title,Message
	$Summary.Title = 'Windows Firewll'
	$Summary.Message = "The Windows Firewall is not running."
	$SummaryArray+= $Summary
}

if ( (@($IPConfig | Where { $_ -match 'Connection-specific DNS Suffix' }) | foreach { $_.Split(':')[-1].Trim() | Where { ('',$null) -notcontains $_ } }).count -gt 0 -and -not ($NETInterface.DHCPEnabled) )
{
	$Summary = '' | Select Title,Message
	$Summary.Title = 'Connection-specific DNS Suffix'
	$Summary.Message = "On the Advanced TCP/IP Settings page, the 'DNS suffix for this connection:'"
	$SummaryArray+= $Summary
}

if ( ('',$null) -notcontains $Proxy -and $Proxy.ProxyEnabled )
{
	$Summary = '' | Select Title,Message
	$Summary.Title = 'Proxy settings detected.'
	$Summary.Message = "Verify that your proxy settings do not interfere with connecting to your  machine(s)."
	$SummaryArray+= $Summary
}


if ( $TokenBloat )
{
	$Summary = '' | Select Title,Message
	$Summary.Title = 'Kerberos Token Bloat'
	$Summary.Message = "Kerberos token bloat has been detected. You may experience intermitten logon issues."
	$SummaryArray+= $Summary
}

if ( $SummaryArray.count -gt 1 )
{
	'' | Out-File $FileName -Append
	"=======================================================================================================================================" | Out-File $FileName -Append
	"======================================== SUMMARY OF SETTINGS THAT NEED TO BE CORRECTED. ===============================================" | Out-File $FileName -Append
	"=======================================================================================================================================" | Out-File $FileName -Append
	
	foreach ( $SA in $SummaryArray )
	{
		"$($SA.Title)`:" | Out-File $FileName -Append
		$SA.Message | Out-File $FileName -Append
		'' | Out-File $FileName -Append
	}
}

#####################################################
if ( $WHOAMI )
{
	OutFile -Title "WHO AM I" -Text $WHOAMI
}

if ( $GetOU -ne $null )
{
	OutFile -Title "Getting the machines OU." -Text $GetOU
}
else
{
	OutFile -Title "Getting the machines OU." -Text "No results were returned."
}

if ( ('',$null) -notcontains $Proxy -and $Proxy.ProxyEnabled )
{
	OutFile -Title "Proxy Information Found" -Text "Proxy is enabled. $($Proxy.ProxyServer)"
}

if ( $KerberosCheck )
{
	OutFile -Title "KERBEROS Token Sizes" -Text $KerberosCheck
}


if ( $Administrators )
{
	OutFile -Title "ADMINISTRATORS" -Text $Administrators
}
else
{
	OutFile -Title "ADMINISTRATORS" -Text "The administrator get came back empty. $($AdminGroupError.Exception)"
}

If ( $SQLLogins )
{
	foreach ( $I in $SQLLogins.keys )
	{
		if ( $I -match 'SQL Login' )
		{
			OutFile -Title "$I" -Text $SQLLogins[$I]
		}
		else
		{
			OutFile -Title "SQL Logins - $I" -Text $SQLLogins[$I]
		}
	}
}

if ( $DynamicPortRangeTCP )
{
	OutFile -Title "TCP - DYNAMIC PORT RANGE" -Text $DynamicPortRangeTCP
}

if ( $DynamicPortRangeUDP )
{
	OutFile -Title "UDP - DYNAMIC PORT RANGE" -Text $DynamicPortRangeUDP
}

if ( $FirewallPorts.InboundRemotePort -ne "NetSecurity module was not available." )
{
	if ( ($FirewallPorts.InboundRemotePort).count -gt 0 )
	{
		OutFile -Title "FIREWALL PORT FILTER - Inbound RemotePort" -Text ([string]::Join(',',($FirewallPorts.InboundRemotePort)))
	}
	else
	{
		OutFile -Title "FIREWALL PORT FILTER - Inbound RemotePort" -Text "No ports found."
	}

	if ( ($FirewallPorts.OutboundRemotePort).count -gt 0 )
	{
		OutFile -Title "FIREWALL PORT FILTER - Outbound RemotePort" -Text ([string]::Join(',',($FirewallPorts.OutboundRemotePort)))
	}
	else
	{
		OutFile -Title "FIREWALL PORT FILTER - Outbound RemotePort" -Text "No ports found."
	}
	if ( ($FirewallPorts.InboundLocalPort).count -gt 0 )
	{
		OutFile -Title "FIREWALL PORT FILTER - Inbound LocalPort" -Text ([string]::Join(',',($FirewallPorts.InboundLocalPort)))
	}
	else
	{
		OutFile -Title "FIREWALL PORT FILTER - Inbound LocalPort" -Text "No ports found."
	}

	if ( ($FirewallPorts.OutboundLocalPort).count -gt 0 )
	{
		OutFile -Title "FIREWALL PORT FILTER - Outbound LocalPort" -Text ([string]::Join(',',($FirewallPorts.OutboundLocalPort)))
	}
	else
	{
		OutFile -Title "FIREWALL PORT FILTER - Outbound LocalPort" -Text "No ports found."
	}
}

if ( $NETInterface -ne $null )
{
	OutFile -Title "Network Interfaces." -Text $NETInterface
}
else
{
	OutFile -Title "Network Interfaces." -Text "Network Interfaces came back empty."
}

if ( $IPConfig )
{
	OutFile -Title "IPCONFIG /ALL" -Text $IPConfig
}

if ( $Services )
{
	OutFile -Title "SERVICES RUNNING" -Text $Services
}

if ( $LMHosts.count -gt 0 )
{
	OutFile -Title "HOST file entries." -Text $LMHosts	
}

if ( $GPArray.count -gt 0 )
{
	OutFile -Title "Group Policy" -Text $GPArray
}
else
{
	OutFile -Title "Group Policy" -Text "The GResults get failed."
}
		
if ( $RoutePrint )
{
	OutFile -Title "ROUTE PRINT" -Text $RoutePrint
}

if ( $Netstat )
{
	OutFile -Title "NETSTAT -an" -Text $Netstat
}
if ( $SharesInfo )
{

    OutFile -Title "SHARES INFORMATION" -Text $SharesInfo
}
if ( $driveInfo )
{

    OutFile -Title "DISK SPACE INFORMATION" -Text $driveInfo
}
if ( $getIISinfo )
{
    OutFile -Title "IIS INFORMATION" -Text $getIISinfo
}
if ( $getInstallApps )
{
    OutFile -Title "INSTALLED APPLICATION INFORMATION" -Text $getInstallApps
}
if ( $getRolesFeatures )
{
    OutFile -Title "INSTALLED FEATURE INFORMATION" -Text $getRolesFeatures
}
if ( $LMHosts )
{

    OutFile -title "HOSTS FILE INFORMATION" -Text $LMHosts
}
