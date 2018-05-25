###################################################################>
Function GetPrismInfo
{
    param([string]$server)
    
    try
    {
        $vstsAuth = "XEUSFORTHEWIN:$VSTS_PERSONAL_ACCESS_TOKEN"
        $vstsAuth = [System.Text.Encoding]::UTF8.GetBytes($vstsAuth)
        $vstsAuth = [System.Convert]::ToBase64String($vstsAuth)
        $headers = @{Authorization=("Basic {0}" -f $vstsAuth)}

        $server = $server.split(".")[0]

        $query = @"
            SELECT [SDMachineName]
              ,[SDEnvironment]
              ,[DriTeam]
              ,[Property]
              ,[Team]
              ,[SD_E_type]
              ,[IsVirtual]
              ,[AreaPath]
              ,[AssignedTo]
              ,[PMOwner]
              ,[DevOwner]
              ,[QualityOwner]
              ,[OpsEscalationAlias]
              ,[OpsOwner]
              ,[Severity]
              ,[VsoState]
              ,[ActiveDirectoryObjectOwner]
              ,[MachineName]
              ,[MachineDomain]
              ,[DnsHostName]
              ,[OrganizationalUnit]
            FROM [PRISMDBV3].[xblcosmosdb].[dbo].[ServerToServiceReportV2]
            WHERE MachineName = '$server';
"@
        $serviceCatalog = Invoke-SQLCmd -Query $query -ServerInstance "Esearch" -QueryTimeout ([int]::MaxValue)
    }
    catch
    {
        $serviceCatalog = "Unable to gather Service Catalog info"
    }
            
    $serviceCatalog 
}#End of
###################################################################>
Function GetIPConfig 
{

    param ([string] $server, [string] $file )
    $IpconfigResults = @()
 
    try
    {
        $IpconfigResults = Invoke-Command -ComputerName $server -ScriptBlock {
            try
            {
                ipconfig /all
            }
            catch
            { 
                "Error in ipconfig pull"
            }
        }
    }
    catch
    {
        $IpconfigResults = "No information found"
    }
    
    
    $IpconfigResults 
    
}# End of 
###################################################################>
function ComputerInfo
{
    param ([string] $server = $env:COMPUTERNAME )
	$Array = @()
    try
    {
        $bytes = (Get-WmiObject -class "cim_physicalmemory" -ComputerName $server | Measure-Object -Property Capacity -Sum).Sum
        $gbMemory = $bytes / 1024 / 1024 / 1024
    
    }
    catch
    {}	
    try
    {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE") 
        $Domain = $rootDse.DefaultNamingContext 
        $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain") 
    
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root) 
        $searcher.Filter = "(&(objectClass=computer)(name=$server))" 
        [System.DirectoryServices.SearchResult]$result = $searcher.FindOne() 
        if (!$?) 
        { 
            return 
        } 
        $dn = $result.Properties["distinguishedName"] 
        $ouResult = $dn.Substring($server.Length) 
     
    }
    catch
    {}	
    try
	{
		$Bios = Get-WmiObject Win32_Bios -ComputerName $server -ErrorAction Stop
	}
	catch 
	{}
	try
	{
		$OS = Get-WmiObject Win32_OperatingSystem -ComputerName $server -ErrorAction Stop
	}
	catch 
	{}
	
	try
	{
		$CS = Get-WmiObject Win32_ComputerSystem -ComputerName $server -ErrorAction Stop
	}
	catch 
	{}
    try
    {
        $CPU = Get-WmiObject Win32_Processor -ComputerName $server -ErrorAction Stop
    }
    catch
    {}
    try
    {
        $s = Get-WmiObject -Class Win32_SystemServices -ComputerName $server -ErrorAction Stop
        if ($s | select PartComponent | where {$_ -like "*ClusSvc*"})
        {
            $Cluster = "Is Clustered"
        }
        else
        {
            $Cluster = "Is Not Clustered"
        }
    }
    catch
    {}
	if ( $Bios -ne $null )
	{
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "SerialNumber"
		$Obj.Value = $Bios.SerialNumber
		$Array+= $Obj
	}
	if ( $ouResult -ne $null )
	{
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Organizational Unit"
		$Obj.Value = $ouResult
		$Array+= $Obj
	}

	if ( $CPU -ne $null )
	{
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "CPU Name"
		$Obj.Value = $CPU.Name
		$Array+= $Obj

		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Number of CPU Cores"
		$Obj.Value = $CPU.Name.Count
		$Array+= $Obj

		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "CPU Description"
		$Obj.Value = $CPU.Description
		$Array+= $Obj
	}
	
	try
	{
		$IEVersion = ((([wmiclass]"\\$($server)\root\default:stdRegProv").GetStringValue(2147483650,"SOFTWARE\Microsoft\Internet Explorer","svcVersion")).sValue).Split('.')[0]
	}
	catch 
	{
		$IEVersion = $null
	}

	if ( $OS -ne $null )
	{

		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Operating System"
		$Obj.Value = $OS.Caption
		$Array+= $Obj
		
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Service Pack"
		$Obj.Value = $OS.ServicePackMajorVersion
		$Array+= $Obj
		
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Last Restart"
		$Obj.Value = $OS.ConvertToDateTime($OS.LastBootUpTime)
		$Array+= $Obj
		
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Server Up Time"
		$TimeSpan = New-TimeSpan $OS.ConvertToDateTime($OS.LastBootUpTime) (Get-Date)
		$Obj.Value = "$($TimeSpan.Days) Day(s) $($TimeSpan.Hours) Hour(s) $($TimeSpan.Minutes) Minute(s)"
		$Array+= $Obj
		
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "OS Version"
		$Obj.Value = $OS.Version
		$Array+= $Obj

		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Build No."
		$Obj.Value = $OS.BuildNumber
		$Array+= $Obj

	}
    if ( $gbMemory -ne $null )
	{
        $memory = "$gbMemory /GB"
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Memory"
		$Obj.Value = $memory
		$Array+= $Obj
		
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Domain"
		$Obj.Value = $CS.Domain
		$Array+= $Obj
	}
	
	if ( $CS -ne $null )
	{
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Model"
		$Obj.Value = $CS.Model
		$Array+= $Obj
		
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Domain"
		$Obj.Value = $CS.Domain
		$Array+= $Obj
	}
    if ( $IEVersion )
	{
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Internet Explorer Version"
		$Obj.Value = $IEVersion
		$Array+= $Obj
	}
	
	if ( $Cluster )
	{
		$Obj = '' | Select $($server),Value
		$Obj."$($server)" = "Cluster"
		$Obj.Value = $Cluster
		$Array+= $Obj
	}
	
	if ( $Array.count -gt 0 )
	{
		$PCArray = $Array
	}
	else
	{
		$PCArray = "No computer information was collected." 
	}
	$PCArray
}# End of ComputerInfo
###################################################################>
## Function for 
Function GetRoutePrint 
{

    param ([string] $server = $env:COMPUTERNAME )

    $hash = @()
    $colItems = get-wmiobject -class "Win32_IP4RouteTable" -namespace "root\CIMV2" -computername $server 
    foreach ($objItem in $colItems) { 
                $itemObject = New-Object PSObject
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Age"-value $objItem.Age 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Caption"-value $objItem.Caption 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Description"-value $objItem.Description 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Destination"-value $objItem.Destination 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Information"-value $objItem.Information 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "InstallationDate"-value $objItem.InstallDate 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "InterfaceIndex"-value $objItem.InterfaceIndex 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Mask"-value $objItem.Mask 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Metric1"-value $objItem.Metric1 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Metric3"-value $objItem.Metric3 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Metric4"-value $objItem.Metric4 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Metric5"-value $objItem.Metric5 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Name"-value $objItem.Name 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "NextHop"-value $objItem.NextHop 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Protocol"-value $objItem.Protocol 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Status"-value $objItem.Status 
                Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Type"-value $objItem.Type 
            $hash +=$itemObject
    } 
    $routeptResult = $hash | Format-Table -Property Age, Caption, Description,Name, Information,Mask,interfaceIndex,Protocol, Status, Type
    $routeptResult

}# End of 
###################################################################>

## Function for 
Function GetRunningServices 
{

    param ([string] $server = $env:COMPUTERNAME )

    $serviceResults = Get-Service -ComputerName $server | Sort Status | Select Status, Name, Displayname | FT -AutoSize
    $serviceResults

}# End of 
###################################################################>
## Function for 
Function GetSQLInfo
{
    param ([string] $server = $env:COMPUTERNAME )
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null
    $sqlResults = @()
    try
    {
        $query = "DECLARE @DBInfo TABLE  
( ServerName VARCHAR(100),  DatabaseName VARCHAR(100),  
FileSizeMB INT,  LogicalFileName sysname,  Fileid INT,
PhysicalFileName NVARCHAR(520),  RecoveryMode sysname,  
FreeSpaceMB INT,  FreeSpacePct VARCHAR(7),  FreeSpacePages INT)  

DECLARE @command VARCHAR(5000), @DriveLetter char(1), @FreeSpaceThreshold char(5)

Set @DriveLetter = '%' --Set this to '%' if you want to check all drives, otherwise specify drive letter e.g. 'S'
Set @FreeSpaceThreshold = 0  --Files with more than this amount of free space are shown.  Set to 0 to see all files

SELECT @command = 'Use [' + '?' + '] SELECT  

' + '''' + '?' + '''' + ' AS DatabaseName,  
CAST(sysfiles.size/128.0 AS int) AS FileSize,  
sysfiles.name AS LogicalFileName, sysfiles.fileid as FileID, 
sysfiles.filename AS PhysicalFileName,  
CONVERT(sysname,DatabasePropertyEx(''?'',''Recovery'')) AS RecoveryMode,  
CAST(sysfiles.size/128.0 - CAST(FILEPROPERTY(sysfiles.name, ' + '''' +   'SpaceUsed' + '''' + ' ) AS int)/128.0 AS int) AS FreeSpaceMB,  
CAST(100 * (CAST (((sysfiles.size/128.0 -CAST(FILEPROPERTY(sysfiles.name,  
' + '''' + 'SpaceUsed' + '''' + ' ) AS int)/128.0)/(sysfiles.size/128.0))  
AS decimal(4,2))) AS varchar(8)) + ' + '''' + '%' + '''' + ' AS FreeSpacePct FROM dbo.sysfiles
where left(sysfiles.filename,1) like ' + ''''  + @DriveLetter + '''' + 'and (sysfiles.size - FILEPROPERTY(sysfiles.name, ' + '''' +   'SpaceUsed' + '''' + ' ))/128 >= ' + @FreeSpaceThreshold 
INSERT INTO @DBInfo  
   (DatabaseName,     FileSizeMB,     LogicalFileName,   Fileid,  
   PhysicalFileName,     RecoveryMode,     FreeSpaceMB,     FreeSpacePct)  
EXEC sp_MSForEachDB @command  

SELECT  DatabaseName, FileSizeMB, FreeSpaceMB, LogicalFileName,  
   Fileid,   PhysicalFileName,     RecoveryMode,     FreeSpacePct,
   'use [' + databasename + '] declare @SizeIncremental int, @FinalSize int, @file sysname
set @file = ' + '''' + LogicalFileName + ''''
+ ' set @FinalSize = ' + cast(FileSizeMB - FreeSpaceMB + 1000 as nvarchar) 
+ ' set @SizeIncremental= ' + cast(FileSizeMB - 1000 as nvarchar) 
+ ' while @SizeIncremental > @FinalSize
Begin
	dbcc shrinkfile(@file,@SizeIncremental)
	set @SizeIncremental= @SizeIncremental - 1000
End
'  as 'ShrinkCommand'

FROM @DBInfo  	
WHERE DatabaseName NOT IN ('master','model','msdb','tempdb') AND PhysicalFileName not like '%.ldf'
ORDER BY  
   freespacemb desc, FileSizeMB desc;"


        $dblist = invoke-sqlcmd -query $query -serverinstance "$server\ "  

        foreach($d in $dblist)
        {
            $listdbs = New-Object PSObject
            Add-Member -InputObject $listdbs -MemberType NoteProperty -name "Computer Name" -value $server
            Add-Member -InputObject $listdbs -MemberType NoteProperty -name "Database Name" -value $d.DatabaseName
            Add-Member -InputObject $listdbs -MemberType NoteProperty -name "Files Size (MB)" -value $d.FileSizeMB
            Add-Member -InputObject $listdbs -MemberType NoteProperty -name "Free Space (MB)" -value $d.FreeSpaceMB
            Add-Member -InputObject $listdbs -MemberType NoteProperty -name "Logical File Name" -value $d.LogicalFileName
            Add-Member -InputObject $listdbs -MemberType NoteProperty -name "Physical File Name" -value $d.PhysicalFileName
            Add-Member -InputObject $listdbs -MemberType NoteProperty -name "Recovery Mode" -value $d.RecoveryMode
            Add-Member -InputObject $listdbs -MemberType NoteProperty -name "Free Space (%)" -value $d.FreeSpacePct
            Add-Member -InputObject $listdbs -MemberType NoteProperty -name "ShrinkCommand" -value $d.ShrinkCommand

            $sqlResults += $listdbs
       
        }
    }
    catch
    {
        $sqlResults = "Unable to collect SQL info"
    }
        $sqlResults





}# End of 
###################################################################>

## Function for 
Function GetHyperVInfo 
{
    param ([string] $server = $env:COMPUTERNAME )
    $vmInfo = @()
    try
    {
        $hyperv = get-service vmms -ComputerName $server -ErrorAction SilentlyContinue
    }
    catch
    {}
        If($hyperv -eq $null)
        {
            $hyperv = "Hyper-V not running or installed on $server"
        }
        
    try
    {
        $results = Get-WMIObject -ComputerName $server –namespace “root\virtualization” -list -ErrorAction SilentlyContinue 
        If ($results)
        {
            $stvm = Get-WMIObject -Class Msvm_ComputerSystem -Namespace “root\virtualization” -ComputerName $server -ErrorAction SilentlyContinue | Select Caption,ElementName,Status,PSComputerName 
        }
        else
        {
            $stVM = "No VM info"
        }
    }
    catch
    {
        $stVM = "No VM info"

    }
    $vmInfo = $hyperv + " " + $stVM
    try
    {

        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $server)
        $RegKey = $Reg.OpenSubKey("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters")
        $hostInfo = $RegKey.GetValue("HostName")
        $vmInfo = $vmInfo + "Names of Host for $server :"
        $vmInfo = $vmInfo + $hostInfo

    }
    catch
    { }
    $vmInfo


}# End of 
###################################################################>

## Function for 
Function GetIISInfo
{

    param ([string] $server = $env:COMPUTERNAME )

    try
    {
        
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $server)
        $RegKey= $Reg.OpenSubKey("SOFTWARE\\Microsoft\\InetStp")
        $IISVersion = $RegKey.GetValue("SetupString")
        If($IISVersion)
        {
            $IISInfo = Invoke-Command -Computername $server -ErrorAction SilentlyContinue -ScriptBlock { import-module WebAdministration; Get-ChildItem -Path IIS:Sites | Select Name,ID,State,PhysicalPath,Binding}
            If(!$IISInfo)
            {
                $IISInfo = $IISVersion

            }
        }

    }
    catch
    {
        $IISInfo = "No IIS installed"

    }
    $IISInfo


}# End of 
###################################################################>

## Function for 
Function GetGPResultInfo
{

    param ([string] $server = $env:COMPUTERNAME )
    $GPResults = @()
    try
    {
        $GPResults = Invoke-Command -Computername $server -ScriptBlock { gpresult /r}
    }
    catch
    {
        $GPResults = "Unable to gather GPResults information"

    }
    $GPResults

}# End of 
 
###################################################################>
function getcertificateInfo
{
        param ([string]$server = $env:COMPUTERNAME)
        $certResults = @()
        try
        {
            $certResults = Invoke-command -ComputerName $server -ScriptBlock 
            {

                


            }
        }
        catch
        {


        }

}# End of
###################################################################>
function getUserLogonInfo
{
        param ([string]$server = $env:COMPUTERNAME)
        try
        {
            $qwinsta = qwinsta /server:$server
            $logins = $qwinsta
        }
        catch
        {}
        try
	    {
            $d = @()
            $source = "\\$server\c$\users"
            $d = dir $source | sort LastWriteTime
            $logins += $d
	    }
	    catch 
	    {}
		try
		{    
			$yesterday = (Get-Date) - (New-TimeSpan -Day 7)
			$LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
			$Results = @()
   

			$Events = Get-WinEvent -LogName $LogName -ComputerName $server -ErrorAction SilentlyContinue | Where-Object {$_.TimeCreated -ge $yesterday}
			foreach ($Event in $Events) {
				$EventXml = [xml]$Event.ToXML()

				$ResultHash = @{
					Server      = $server
					Time        = $Event.TimeCreated.ToString()
					'Event ID'  = $Event.Id
					'Desc'      = ($Event.Message -split "`n")[0]
					Username    = $EventXml.Event.UserData.EventXML.User
					'Source IP' = $EventXml.Event.UserData.EventXML.Address
					'Details'   = $Event.Message
				}

				$Results += (New-Object PSObject -Property $ResultHash)
			}
            
			$logins += $results
		}
		catch
		{
            $logins += Get-EventLog -ComputerName $server System -Source Microsoft-Windows-Winlogon -ErrorAction SilentlyContinue | select $UserProperty,$TypeProperty,$TimeProeprty
            if($logins.Length -eq 0)
            {
			    $logins = "Error received when retrieving login information"
            }
		}
        
        if($logins.Length -eq 0)
        {
            $logins = Get-EventLog -ComputerName $server System -Source Microsoft-Windows-Winlogon | select $UserProperty,$TypeProperty,$TimeProeprty
        }
        
		$logins
      
}# End of 
###################################################################>
## Function for 
Function GetNetStat 
{

    param ([string] $server = $env:COMPUTERNAME )
    $netstat = @()
    try
    {
        $netstat = Invoke-Command -ComputerName $server -ScriptBlock {netstat -aon}

    }
    catch
    {
        $netstat = "No unable to collect netstat info"
    }
    $netstat



}# End of 
###################################################################>

## Function for 
Function GetFileShareInfo 
{

    param ([string] $server = $env:COMPUTERNAME )
    $s = @()
    try
    {
        $s=New-CimSession -ComputerName $server
            Get-SmbShare -Session $s|foreach{
            Get-SmbShareAccess $_.name -Session $s}
    }
    catch
    {
        $s = "No shares to report on"

    }

    $s

}# End of 
###################################################################>

## Function for 
Function GetCertInfo
{

    param ([string] $server = $env:COMPUTERNAME )
    $certificates = @()
    try
    {
        $certificates = Invoke-Command -ComputerName $server -ScriptBlock {
            try
            {
                Get-ChildItem Cert:\ -Recurse 
            }
            catch
            { 
                "Error in cert pull"
            }
        }
    }
    catch
    {
        $certificates = "No certificates found"
    }
    $certificates


}# End of
 
###################################################################>

function getRolesFeatures
{
    param ([string] $server = $env:COMPUTERNAME )
    $rolesFeatures = @()
    try
    {
        $rolesFeatures = Get-WmiObject -class Win32_ServerFeature -ComputerName $server -ErrorAction SilentlyContinue | Select Name, ID
    }
    catch
    {
        $rolesFeatures = "Unable to gather Windows Features on this system"
    }
    $rolesFeatures
}# End of Roles Features
###################################################################>

Function GetScheduleTasks
{
        param(
	        [string]$server = $env:COMPUTERNAME,
			[string]$filename
        )
		try
		{
			schtasks /query /s $server /fo LIST /v | Out-File -FilePath $filename -Append

		}
		catch
		{

			"Unable to gather schedule tasks info on $server" | out-file -FilePath $filename 
		}



}# End of getScheduleTasks
###################################################################>

## Function for 
Function GetDriveFoldInfo 
{

    param ([string] $server = $env:COMPUTERNAME )
    # Get the Disks for this computer
    $diskspace = New-Object System.Collections.Generic.List[System.Object]
    $diskspace.add("$server   Dir  Free  Total/GB")
    $diskspace.add("_______________________________________")
    $colDisks = get-wmiobject Win32_LogicalDisk -computername $server -Filter "DriveType = 3"
    # For each disk calculate the free space
        foreach ($disk in $colDisks) 
        {
            if($disk.Size -ne $null)
            {
                $size = $disk.FreeSpace/$disk.Size
                $TotalSpace = [System.Math]::Round($disk.Size/1GB)
                If($size -gt 0){
                    $PercentFree = [Math]::Round($size * 100)
                }
                $Drive = $disk.DeviceID
                $diskspace.Add("$server - $Drive - $PercentFree% - $TotalSpace in GB")
            }
        }
    $diskspace

}# End of 
###################################################################>

## Function for 
Function GetAppEvntvwr 
{

    param ([string] $server = $env:COMPUTERNAME, [string] $file )
	try
	{
		$time1 = ((get-date).toUniversalTime()).addHours(0)
		$time2 = ((get-date).toUniversalTime()).addHours(-24)
		$newest = get-date($time1) -f s
		$oldest = get-date($time2) -f s
		$serverpath = "\\" + $server + "\c$\temp"
		if(!(Test-Path $serverpath))
		{
    
			New-Item -ItemType Directory -Force -Path $serverpath -ErrorAction SilentlyContinue
		}
        if(!(Test-Path $file))
		{
    
			New-Item -ItemType Directory -Force -Path $file -ErrorAction SilentlyContinue
		}
		$logname = "Application"
    
		WEVTUTIL.EXE epl $logName C:\temp\$server$logName.evtx "/q:*[System[TimeCreated[@SystemTime<=`'$newest`' and @SystemTime>=`'$oldest`']]]" /r:$server /ow:true
		$source = $serverpath +"\$server$logName.evtx"
		Copy-Item -Path $source -Destination $file -ErrorAction SilentlyContinue
	
		
	}
	catch
	{
		$outFile = $file + "\ErrorsCollectionData_$server.txt"
		"Unable to retrieve Application event information" | Out-File -FilePath $outFile
	}

}# End of 
 
###################################################################>

## Function for 
Function GetSecEvntvwr
{
    param ([string] $server = $env:COMPUTERNAME, [string] $file )
	try
	{
		$time1 = ((get-date).toUniversalTime()).addHours(0)
		$time2 = ((get-date).toUniversalTime()).addHours(-4)
		$newest = get-date($time1) -f s
		$oldest = get-date($time2) -f s
		$serverpath = "\\" + $server + "\c$\temp"
		if(!(Test-Path $serverpath))
		{
    
			New-Item -ItemType Directory -Force -Path $serverpath -ErrorAction SilentlyContinue
		}
        if(!(Test-Path $file))
		{
    
			New-Item -ItemType Directory -Force -Path $file -ErrorAction SilentlyContinue
		}
		$logname = "Security"
    
		WEVTUTIL.EXE epl $logName C:\temp\$server$logName.evtx "/q:*[System[TimeCreated[@SystemTime<=`'$newest`' and @SystemTime>=`'$oldest`']]]" /r:$server /ow:true
		$source = $serverpath +"\$server$logName.evtx"
		Copy-Item -Path $source -Destination $file -ErrorAction SilentlyContinue
	
		
	}
	catch
	{
		$outFile = $file + "\ErrorsCollectionData_$server.txt"
		"Unable to retrieve Security event information" | Out-File -FilePath $outFile
	}

}# End of
###################################################################>

## Function for 
Function GetSysEvntvwr
{
    param ([string] $server = $env:COMPUTERNAME, [string] $file )
	try
	{
		$time1 = ((get-date).toUniversalTime()).addHours(0)
		$time2 = ((get-date).toUniversalTime()).addHours(-24)
		$newest = get-date($time1) -f s
		$oldest = get-date($time2) -f s
		$serverpath = "\\" + $server + "\c$\temp"
		if(!(Test-Path $serverpath))
		{
    
			New-Item -ItemType Directory -Force -Path $serverpath -ErrorAction SilentlyContinue
		}
        if(!(Test-Path $file))
		{
    
			New-Item -ItemType Directory -Force -Path $file -ErrorAction SilentlyContinue
		}
		$logname = "System"
    
		WEVTUTIL.EXE epl $logName C:\temp\$server$logName.evtx "/q:*[System[TimeCreated[@SystemTime<=`'$newest`' and @SystemTime>=`'$oldest`']]]" /r:$server /ow:true
		$source = $serverpath +"\$server$logName.evtx"
		Copy-Item -Path $source -Destination $file -ErrorAction SilentlyContinue
	
		
	}
	catch
	{
		$outFile = $file + "\ErrorsCollectionData_$server.txt"
		"Unable to retrieve Application event information" | Out-File -FilePath $outFile
	}

}# End of
###################################################################>

## Function for 
Function GetFirewallRules 
{

    param ([string] $server = $env:COMPUTERNAME )
    $FireWallRule = @()
    $fwrules = New-Object System.Collections.ArrayList
    
    $s=New-CimSession -ComputerName $server
    $FireWallRule = Get-NetFirewallRule -CimSession $s -ErrorAction Stop | Select DisplayName,Description,Enabled,Profile,Direction,Action,PrimaryStatus | format-list 
    $FireWallRule

}# End of 
###################################################################>

## Function for 
Function GetLocalAdmininfo
{

    param ([string] $server = $env:COMPUTERNAME )
    $localadmin = @()
    try
    {
        $localadmin = Invoke-Command -ComputerName $server -ScriptBlock {
            try
            {
                Net localgroup administrators
            }
            catch
            { 
                "Error in local admin pull"
            }
        }
    }
    catch
    {
        $localadmin = "invoke command error"
    }
    $localadmin


}# End of
###################################################################>
function Get-iLOInfo
{
    param ([string] $server = $env:COMPUTERNAME)
    $outObj = @()
    try
    {
	    
		$ilo=get-wmiobject -class hp_managementprocessor -computername $server -namespace root\HPQ -ErrorAction SilentlyContinue
		if ($ilo -eq $Null) 
        {
            $outObj = "Unable to gather iLO info on $server"

        }
        else
        {
            $itemObject = New-Object PSObject
            Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Server"-value $server 
            Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Description"-value $ilo.Description
            switch ($ilo.ActiveLicense) 
            {
                1
                {
                    Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Active License"-value $ilo.ActiveLicense
                    break;
                }
                2
                {
                    Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Active License"-value $ilo.ActiveLicense
                    break;
                }
                3
                {
                    Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Active License"-value $ilo.ActiveLicense
                    break;
                }
                4
                {
                    Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Active License"-value $ilo.ActiveLicense
                    break;
                }
                5
                {
                    Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Active License"-value $ilo.ActiveLicense
                    break;
                }
                default
                {
                    Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Active License"-value $ilo.ActiveLicense
                    break;
                }
                
            } 
            Add-Member -InputObject $itemObject -MemberType NoteProperty -name "IP Address"-value $ilo.ipaddress
            Add-Member -InputObject $itemObject -MemberType NoteProperty -name "IPV4 Subnet Mask"-value $ilo.ipv4subnetmask 
            Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Hostname"-value $ilo.hostname
            Add-Member -InputObject $itemObject -MemberType NoteProperty -name "Gateway IP Address"-value $ilo.GatewayIPAddress 
            Add-Member -InputObject $itemObject -MemberType NoteProperty -name "License Key"-value $ilo.LicenseKey
            Add-Member -InputObject $itemObject -MemberType NoteProperty -name "iLO URL"-value $ilo.URL  
            $outObj +=$itemObject

        }

    }
    catch
    {
            $outObj = "Unable to gather iLO info on $server"

    }


    $outObj


}# End of
###################################################################>
## Function for creating outfile.
function OutFile
{
	param ( $Text, [string]$Title, [string]$File )
	
	$MessageLength = ("$Title $(Get-Date -format 'MM/dd/yyyy')").length
	
	'' | Out-File $File -Append
	"=======================================================================================================================================" | Out-File $File -Append
	"============================== $Title $(Get-Date -format 'MM/dd/yyyy') " + ('='.PadRight((103 - $MessageLength),'=')) | Out-File $File -Append
	"=======================================================================================================================================" | Out-File $File -Append
	$Text | Out-File $File -Append
}# End of Outfile
Function Start-ReportingProcess
{
    Param (
        [string] $server,
        [string] $report 
    )
    Write-host -NoNewLine "`t`t` $server report $userentry is starting, do not close window.."
    $DateTime = $(Get-Date -format 'yyyy_MM_dd_HHmmss')
    $path = "$HOME\Desktop\XEUSInventory\$server"
    If(!(test-path $path))
    {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
    }

    Write-Host -NoNewline "."
	sleep -s 1
    $FileName = "$path\$($server)_$($report)_Info_$DateTime.txt"
    Write-Host -NoNewline "."
	sleep -s 1

    try
    {
        #Test-Connection -ComputerName $server -ErrorAction Stop | Out-Null
        Write-Host -NoNewline "."
	    sleep -s 1
    
        Switch ($report)
        {

            "standard"
            {
			    $serverInfo = @()
			    $serverInfo = ComputerInfo -server $server
			    OutFile -Title "Computer Information" -Text $serverinfo -File $FileName 
                $Ipconf = @()
			    $Ipconf = GetIPConfig -server $server -file $FileName
			    OutFile -Title "Ipconfig Information" -Text $Ipconf -File $FileName 
			    $inforoles = @()
                $inforoles = getRolesFeatures -server $server 
                OutFile -Title " Roles/Feature Information" -Text $inforoles -File $FileName
			    $info = @()
                $info = GetLocalAdmininfo -server $server 
                OutFile -Title "Local Admin Information" -Text $info -File $FileName  
			    $info = @()
                $info = GetRunningServices -server $server 
                OutFile -Title "Services Information" -Text $info -File $FileName
			    $info = @()
                $info = GetRoutePrint -server $server 
                OutFile -Title "Route Print Information" -Text $info -File $FileName
                Write-Host -NoNewline "."
	            sleep -s 1
                break
            }
		    "ilo"
            {
                $info = @()
                $info = Get-iLOInfo -server $server 
                OutFile -Title "iLO Information" -Text $info -File $FileName 
                Write-Host -NoNewline "."
	            sleep -s 1 
                break
            }
		    "logons"
            {
                $info = @()
                $info = getUserLogonInfo -server $server -Days 2
                OutFile -Title "Logon Information" -Text $info -File $FileName 
                Write-Host -NoNewline "."
	            sleep -s 1  
                break
            }
		    "sql"
            {
                $info = @()
                $info = GetSQLInfo -server $server 
                OutFile -Title "SQL Information" -Text $info -File $FileName
                Write-Host -NoNewline "."
	            sleep -s 1   
                break
            }
		    "hyperv"
            {
                $info = @()
                $info = GetHyperVInfo -server $server 
                OutFile -Title "Hyper-V Information" -Text $info -File $FileName 
                Write-Host -NoNewline "."
	            sleep -s 1  
                break
            }
		    "iis"
            {
                $info = @()
                $info = GetIISInfo -server $server 
                OutFile -Title "IIS Information" -Text $info -File $FileName
                Write-Host -NoNewline "."
	            sleep -s 1   
                break
            }
		    "gpresults"
            {
                $info = @()
                $info = GetGPResultInfo -server $server 
                OutFile -Title "GP Results Information" -Text $info -File $FileName
                Write-Host -NoNewline "."
	            sleep -s 1   
                break
            }
		    "netstat"
            {
                $info = @()
                $info = GetNetStat -server $server 
                OutFile -Title "Netstat Information" -Text $info -File $FileName 
                Write-Host -NoNewline "."
	            sleep -s 1  
                break
            }
		    "fileshare"
            {
                $info = @()
                $info = GetFileShareInfo -server $server 
                OutFile -Title "Fileshare Information" -Text $info -File $FileName
                Write-Host -NoNewline "."
	            sleep -s 1   
                break
            }
		    "cert"
            {
                $info = @()
                $info = GetCertInfo -server $server 
                OutFile -Title " Certificate Information" -Text $info -File $FileName
                Write-Host -NoNewline "."
	            sleep -s 1   
                break
            }
		    "schtasks"
            {
                $info = @()
			    #$CSVName = "$path\$($server)_$($report)_Info_$DateTime.csv"
                $FileName = "$path\$($server)_$($report)_Info_$DateTime.txt"
                $info = GetScheduleTasks -server $server -filename $FileName 
                break
            }
		    "drive"
            {
                $info = @()
                $info = GetDriveFoldInfo -server $server 
                OutFile -Title " Drive Information" -Text $info -File $FileName  
                break
            }
		    "eventvwrapp"
            {
                $info = @()
			    $info = GetAppEvntvwr -server $server -file $path 
                break
            }
		    "eventvwrSec"
            {
                $info = @()
			    $info = GetSecEvntvwr -server $server -file $path 
                break
            }
		    "eventvwrsys"
            {
			    $info = @()
			    $info = GetSysEvntvwr -server $server -file $path 
                break
            }
		    "firewall"
            {
                $info = @()
                $info = GetFirewallRules -server $server 
                OutFile -Title "Firewall Information" -Text $info -File $FileName  
                break
            }
            "prism"
            {
                $info = @()
                $info = GetPrismInfo -server $server
                OutFile -Title "Prism Information" -Text $info -File $FileName  
                break
            }
            default    
            {
                $defaultFile = $path + "\default.txt"
                "something $report" | Out-File -FilePath $defaultFile -Append
                break
            }



        }
        Write-Host "done"
	    sleep -s 1 
    }
    catch
    {
        "Errors while trying to connect to $server.  Please sure the server is online." | Out-File -FilePath $FileName -Append
    }
}
function runreports
{
    param([string]$server,[string] $userentry)
    
    try
    {
        Test-Connection -ComputerName $server | Out-Null
        <#$si = New-object System.Diagnostics.ProcessStartInfo
        $si.CreateNoWindow = $true
        $si.UseShellExecute = $false
        $si.RedirectStandardOutput = $true
        $si.RedirectStandardError = $true
        $si.FileName = "$psHome\powershell.exe"
        $si.Arguments = @("-file C:\Users\v-eljaeg\Desktop\XEUSServerInventory\XEUS-ServerInventory.ps1 -server $server -report $userentry")
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $si
        [void]$proc.Start()
        
        Write-host -NoNewLine "`t`t` $server report $userentry is starting, do not close window.."
        While(!($proc.HasExited))
        { 
	        Write-Host -NoNewline "."
	        sleep -s 2

        }
        $proc.WaitForExit()
        Write-host "done"#>
        Start-ReportingProcess -server $server -report $userentry
                           
    }
    catch
    {
        write-Host "Something went wrong in the loops of reports"
        Start-Sleep -Seconds 5
    }

}
function loadMainMenu()
{
    [bool]$loopMainMenu = $true
    $list = @()
    $l = @()
    $selection = ""
    while ($loopMainMenu)
    {
    Clear-Host  # Clear the screen.
    Write-Host  -ForegroundColor White  “`n`tXEUS TEAM – Server Inventory Report– Version 1.0`t`n”
    Write-Host  -ForegroundColor White  “`t`tMain Menu`t`t`n”
    $runasAlias = [Environment]::UserName
    Write-Host  -ForegroundColor White "Running as: $runasAlias`n"
    Write-Host “`t`t`t1  - Report on PRISM Info         1”
    Write-Host “`t`t`t2  - Report on iLO Info           2”
    Write-Host “`t`t`t3  - Report on User Login History 3”
    Write-Host “`t`t`t4  - Report on SQL Info           4”
    Write-Host “`t`t`t5  - Report on Hyper-V Info       5”
    Write-Host “`t`t`t6  - Report on IIS info           6”
    Write-Host “`t`t`t7  - Report on GPResults Info     7”
    Write-Host “`t`t`t8  - Report on Netstat Info       8”
    Write-Host “`t`t`t9  - Report on Cert Info          9”
   Write-Host “`t`t`t10 - Report on Schedule Tasks     10”
   Write-Host “`t`t`t11 - Report on Drive Info         11”
   Write-Host “`t`t`t12 - Report on Application Events 12”
   Write-Host “`t`t`t13 - Report on Security Events    13”
   Write-Host “`t`t`t14 - Report on System Events      14”
   Write-Host “`t`t`t15 - Report on Firewall Info      15”
   Write-Host “`t`t`t16 - Report on Standard Info      16”
    Write-Host “`t`t`tQ --- Quit And Exit`n”
    Write-Host -ForegroundColor Yellow "`NOTICE:`t"
    Write-Host -ForegroundColor White  "`The reports will save to your desktop under 'XEUS Inventory' folder.`t`n"
    write-Host “Enter a Menu Option Number(s) - ex: 1 or 1 4 6 7 separated"
    $mainMenu = Read-Host "by a space or enter 'all' to select all reports” # Get user's entry.
    $trimentry = $mainMenu.Trim() 
    If($trimentry.Length -eq 0)
    {
        $loopMainMenu = $false
    }
    
    $l = $trimentry.Split(" ") 
    $array = @()
    $list = $l | select -Unique
    
    foreach($r in $list)
        {
               
            switch ($r)
            {
                1
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "prism"
                    $Obj.Display = "Prism Info"
                }# 
                2
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "ilo"
                    $Obj.Display = "iLo Info"
                } #
                3
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "logons"
                    $Obj.Display = "User Login History"
                } #
                4
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "sql"
                    $Obj.Display = "SQL Info"
                } #
                5
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "hyperv"
                    $Obj.Display = "Hyper-V Info"
                } # 
                6
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "iis"
                    $Obj.Display = "IIS Info"
                } #
                7
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "gpresults"
                    $Obj.Display = "GPResults Info"
                } #
                8
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "netstat"
                    $Obj.Display = "Netstat Info"
                } #
                9
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "cert"
                    $Obj.Display = "Cert Info"
                } # 
                10
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "schtasks"
                    $Obj.Display = "Schedule Tasks"
                } #
                11
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "drive"
                    $Obj.Display = "Drive Info"
                } #
                12
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "eventvwrapp"
                    $Obj.Display = "Application Events"
                } #
                13
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "eventvwrsec"
                    $Obj.Display = "Security Events"
                } # 
                14
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "eventvwrsys"
                    $Obj.Display = "System Events"
                } #
                15
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "firewall"
                    $Obj.Display = "Firewall Info"
                } #
                16
                {
                    $Obj = '' | Select Report, Display
                    $Obj.Report = "standard"
                    $Obj.Display = "Standard Info"
                } #
                "all"
                {
                    $ObjR = @{Report="prism","ilo","logons","sql","hyperv","iis","gpresults","netstat","cert","schtasks","drive","eventvwrapp","eventvwrsec","eventvwrsys","firewall","standard"} 
                    $ObjD = @{Display="Prism Info","iLO Info","Logons History","SQL Info","Hyper-V Info","IIS Info","GPResults Info","Netstat Info","Cert Info","Schedule Tasks","Drive Info","Application Events","Security Events","System Events","Firewall Info","Standard Info"}        
                    $Obj = @()
                    for($i = 0;$i -lt 16;$i++)
                    {
                        $ObjStore = New-Object psobject
                        $Objstore | add-member –membertype NoteProperty –name Report –Value $ObjR.Report[$i]
                        $Objstore | add-member –membertype NoteProperty –name Display –Value $ObjD.Display[$i]
                        $Obj += $ObjStore 
    
                    }
                } #
                "q" 
                {
                    $loopMainMenu = $false
                    Clear-Host
                    Write-Host -BackgroundColor DarkCyan -ForegroundColor Yellow "`t`t`t`t`t"
                    Write-Host -BackgroundColor DarkCyan -ForegroundColor Yellow "`tGoodbye!`t`t`t"
                    Write-Host -BackgroundColor DarkCyan -ForegroundColor Yellow "`t`t`t`t`t"
                    sleep -Seconds 1
        
                    Clear-Host
                    return $false

                }
                default 
                {
                    $selection = "default"
                    Write-Host -BackgroundColor Red -ForegroundColor White "You did not enter a valid selection. Please enter a valid selection."
                    sleep -Seconds 2
                    return $true
                }
            }# End switch
                
            If($selection -ne "default")
            {
                $array += $Obj
            }    
            

                
        }# End foeach

        If($selection -ne "default")
        {
            $i = $array.Count
            mainMenuOption1 -reports $array -rct $i
        }
        
        
    }
    return $false
}

function mainMenuOption1()
# This section is used for Loading Main Menu Option 1, .
{
    param($reports, $rct)
    [bool]$loopSubMenu = $true
    while ($loopSubMenu)
    {
        
        Clear-Host  # Clear the screen.
        Write-Host  -ForegroundColor White  “`n`tXEUS TEAM – Server Inventory Report– Version 1.0`t`n”
        Write-Host  -ForegroundColor White  “`t`tServer(s) $selection Reports `t`t`n”
        $runasAlias = [Environment]::UserName
        Write-Host  -ForegroundColor White "Running as: $runasAlias`n"
        Write-Host  -ForegroundColor White "Reports "
        Write-Host  -ForegroundColor White "======= "
        for ($i = 0; $i -lt [int]$rct;$i++)
        {
            Write-Host $reports[$i].Display
        }
        Write-Host “`n`t`t`tYou can enter into the menu option either the ”
        Write-Host “`t`t`tname of a server or the path and file name    ”
        Write-Host “`t`t`tto a list of servers.”
        Write-Host “`t`t`t”
        Write-Host “`t`t`tOr enter 'Q' which will quit this menu and return to Main Menu`n"
        $scriptPath = Split-Path $MyInvocation.InvocationName
        Write-Host "       $scriptPath      "
        $subMenu = Read-Host “`t`tEnter server name or the path and name of the file containing your list of servers”
        If($subMenu.Length -eq 0)
        {
            Write-Host -BackgroundColor Red -ForegroundColor White "You did not enter a valid selection. Please enter a valid selection."
            sleep -Seconds 2
            $loopSubMenu = $false
        }
        if($subMenu -eq 'q')
        {
            $loopSubMenu = $false
        }
        else
        {
            try
            {
                
                $valid = "False"
                Clear-host
                Write-Host "Starting the generation of reports:"
                $valid = Test-Path -Path $subMenu -ErrorAction SilentlyContinue
                If($valid -eq "True")
                {
                    $serverlist = get-content $subMenu
                    foreach($r in $reports.Report)
                    {   
                        foreach($server in $serverlist)
                        {                         
                            runreports -server $server -userentry $r

                        }
                    }
                }
                else
                { 
                    $server = $subMenu
                    Test-Connection -ComputerName $server | Out-Null
                    foreach($r in $reports.Report)
                    {
                        runreports -server $server -userentry $r
                    }  
                }

            }
            catch
            {
                Write-host "Something Went wrong with the your entry: $subMenu"
                Start-Sleep -Seconds 7
            }
             
        }
        $loopSubMenu = $false   
    }
    Invoke-item $HOME\Desktop\XEUSInventory\
}

# Start the Menu once loaded:

# Get the ID and security principal of the current user account
 $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
 $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
  
 # Get the security principal for the Administrator role
 $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
  
 # Check to see if we are currently running "as Administrator"
 if ($myWindowsPrincipal.IsInRole($adminRole))
    {
    # We are running "as Administrator" - so change the title and background color to indicate this
    $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
    $Host.UI.RawUI.BackgroundColor = "DarkBlue"
    clear-host
    }
 else
    {
    # We are not running "as Administrator" - so relaunch as administrator
    
    # Create a new process object that starts PowerShell
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    
    # Specify the current script path and name as a parameter
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    
    # Indicate that the process should be elevated
    $newProcess.Verb = "runas";
    
    # Start the new process
    [System.Diagnostics.Process]::Start($newProcess);
    
    # Exit from the current, unelevated, process
    #exit
    }
$results = loadMainMenu
while($results -eq "True")
{
    
    $results = loadMainMenu
}


