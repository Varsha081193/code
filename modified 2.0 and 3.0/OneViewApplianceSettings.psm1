##############################################################################
# Name: OneViewApplianceSettings.psm1 
# 
# Description: Wrapper functions to achieve oneview create backup and restore
#              functionalities. It uses HPOneView.200.psm1 module to
#              to invoke rest api of oneview
# 
# Date: Mar 2016 
##############################################################################


Import-Module .\HPOneView.200.psm1
Import-Module .\Utility.psm1

#*****************************************
$Global:root = $PWD
$Global:RestoreUri = "/rest/restores"
$Global:file = "$Global:root\Input_JSON_files\restore_back.json"
$Global:device="eth0"

#*****************************************

function Create_and_downloadBackups
{
    Param
    (
        [parameter(Mandatory = $true,ValueFromPipeline = $false,ParameterSetName = "default",HelpMessage = "Specify the folder location to save the appliance backup file.",Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("save")]
        [string]$Location
    )

    Process 
    {
        writeLog "FUNCTION BEGIN : CREATE AND DOWNLOAD BACKUPS"

        #invoking library function to set backup
        $resp = New-HPOVBackup $Location

        writeLog "The backup file is present in the $Location"
        Write-Host "The backup file is present in the $Location"

        writeLog "FUNCTION END : CREATE AND DOWNLOAD BACKUPS"

    }
}

function Restore_BackUp
{
    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List . Enter the backup file without the extension (eg:ci-000c2968c373_backup_2016-04-07_000810)")]
        [ValidateNotNullOrEmpty()]
        [System.String]$BackUpFile     

    )

    Process 
    {
        writeLog "FUNCTION BEGIN : RESTORE BACKUP"

        #creates POST request JSON body for restore backup
        $path = Get-Content $Global:file -Raw| ConvertFrom-Json
        $path | add-member -NotePropertyName uriOfBackupToRestore  -NotePropertyValue "/rest/backups/$BackUpFile"
        $response = Send-HPOVRequest -uri $Global:RestoreUri POST $path
        $respuri = $response.uri
 
        $resp = Send-HPOVRequest -uri $respuri GET
        if($resp.status -eq "IN_PROGRESS")
        {
            writeLog "Restoring $ApplianceIP in Progress"
            Write-Host "Restoring $ApplianceIP in Progress"
        }
        if($resp.status -eq "FAILED")
        {
            $errorMessage = $resp.errorMessage
            writeLog "Failed to restore the backup : $errorMessage"
            Write-Host "Failed to restore the backup : $errorMessage"
        }
        writeLog "FUNCTION END : RESTORE BACKUP"
    }
}

function Apply_FirstTimeSetup([string]$inputFilename, [string]$appUsername, [string]$appPassword)
{
    <#
        .DESCRIPTION
        Establish a connection with appliance ,reset the password and apply the network configuration on an appliance.

        .PARAMETER 
        Input file with json format
        Appliance Username
        Appliance Password
    #>

	writeLog "Entering Apply_FirstTimeSetup()..."
	Write-Host "." -NoNewline
	
	#read inputs from file

	$inputsToConfig = Get-Content $inputFilename -Raw | ConvertFrom-Json
	
	$myApplianceIP = $inputsToConfig.ciApplianceipAddress
	$global:dhcpIpAddress = $myApplianceIP
	
	$mySupportAccess = $inputsToConfig.supportAccess     # Allow HP support access to appliance
	
	# NOTE: actual desired appliance configuration:
    $myHostname = $inputsToConfig.ciApplianceHostname     # Fully-qualified DNS name
	
    # IPv4 Config
	$myIpv4Type = $inputsToConfig.IPv4.ipv4Type           # "DHCP", "STATIC" or "UNCONFIGURE"
	$myIpv4Addr = $inputsToConfig.IPv4.ipv4Addr           # "www.xxx.yyy.zzz" (blank for DHCP)
	$global:globalmyIpv4Type = $myIpv4Addr
	$myIpv4Subnet = $inputsToConfig.IPv4.ipv4Subnet       # "www.xxx.yyy.zzz" (blank for DHCP)
	$myIpv4Gateway = $inputsToConfig.IPv4.Ipv4Gateway     # "www.xxx.yyy.zzz" (blank for DHCP)
	
    # IPv6 Config
	$myIpv6Type = $inputsToConfig.IPv6.ipv6Type           # "DHCP", "STATIC" or "UNCONFIGURE"
	$myIpv6Addr = $inputsToConfig.IPv6.ipv6Addr           # "ssss:tttt:uuuu:vvvv:wwww:xxxx:yyyy:zzzz"
	$myIpv6Subnet = $inputsToConfig.IPv6.ipv6Subnet       # "ffff:ffff:ffff:ffff:0:0:0:0"
	$myIpv6Gateway = $inputsToConfig.IPv6.ipv6Gateway     # "ssss:tttt:uuuu:vvvv:wwww:xxxx:yyyy:zzzz"
	
    # DNS Config
	$myDynamicDns = $inputsToConfig.DNS.dynamicDns        # "true" or "false" (case sensitive, for now)
	$myDomainName = $inputsToConfig.DNS.domainName
	$mySearchDomains = $inputsToConfig.DNS.searchDomains  # {"my.com", "other.com"}
	$myNameServers = $inputsToConfig.DNS.nameServers      # {"11.22.33.44", "11.22.33.55"}
	
    # Appliance Time/NTP Configuration
	$myNtpServers = $inputsToConfig.applianceTimeNTP.ntpServers     # {"ntp.local.com", "backup.ntp.com"}
	$myDateTime = $inputsToConfig.applianceTimeNTP.dateTime         # ISO-8601 format: "yyyy-MM-ddTHH:mm:ss.sssZ"
	$myTimezone = $inputsToConfig.applianceTimeNTP.timezone        # "America/Denver" call Get-TimezoneList()	
	
	#check if password has already been changed. meaning connect with changed password
	writeLog "check if password has already been changed. meaning connect with changed password and changed ip"
	writeLog "If it fails, this means ip and password has not changed. And you can ignore the exceptions."
	writeLog "It will go ahead and try to accept EULA, changed password"
	try
    {
	    $returncode = Connect-HPOVMgmt -appliance $myApplianceIP -user $appUsername -password $appPassword -authProvider "LOCAL"
	} 
    catch
    {
        writeLog -message ""
    }
	
	if ($returncode -ne "OK")
	{            `
	    # First check if the EULA has been accepted
		if (Get-HPOVEulaStatus -appliance $myApplianceIP)
		{
			writeLog "Accepting EULA..."
			$EulaStatus=Set-HPOVEulaStatus $mySupportAccess -appliance $myApplianceIP
		}
		
		writeLog "Trying to connect with default password"

		# For initial setup, connect first using "default" Administrator credentials:
		try
		{
			
			$ret = Connect-HPOVMgmt -appliance $myApplianceIP -user $appUsername -password $appPassword -authProvider "LOCAL"
            $ret = $ret | ConvertFrom-Json
			if ($ret.errorCode -match "PASSWORD_CHANGE_REQUIRED")
			{
				# Initial setup - password change required:
				writeLog "Update password - Enter new adminstrator password"
                $NewappPassword = Read-Host "Enter the new password"
				Set-HPOVInitialPassword -userName $appUsername -oldPassword $appPassword -newPassword $NewappPassword
			}
		}
		catch
		{
			writeLog "Error:Unable to change password" -debuglevel "ERROR"
			writeLog "$_.Exception" -debuglevel "ERROR"
            Write-Host "Unable to change password"
			
		}
		
		writeLog "Trying to connect with changed password"
		
		# Now, connect again, normally, with new password
        $retAfterChangedPasswd = Connect-HPOVMgmt -appliance $myApplianceIP -user $appUsername -password $NewappPassword -authProvider "LOCAL"
		writeLog "Before updating appliance with network configuration"
		
		# Update appliance networking configuration
		try
		{
            Set-HPOVApplianceNetworkConfig  -hostname $myHostname -device $device -interfaceName "Appliance"  `
										    -ipv4Type $myIpv4Type -ipv4Addr $myIpv4Addr -ipv4Subnet $myIpv4Subnet `
										    -ipv4Gateway $myIpv4Gateway -ipv6Type $myIpv6Type -ipv6Addr $myIpv6Addr `
										    -ipv6Subnet $myIpv6Subnet -ipv6Gateway $myIpv6Gateway -overrideDhcpDns $myDynamicDns `
										    -domainName $myDomainName -searchDomains $mySearchDomains -nameServers $myNameServers -ntpServers $myNtpServers
		}
		catch
		{
			writeLog "Error occured in updating appliance network configuration" -debuglevel "ERROR"
			writeLog "$_.Exception" -debuglevel "ERROR"
            Write-Host "Network setting cannot apply"
		}
		
	}
	else
	{
		writeLog "FTS already completed, able to connect to appliance with changed ip and changed password successfully..."
	}
	
	writeLog "Exiting Apply_FirstTimeSetup()..."
}