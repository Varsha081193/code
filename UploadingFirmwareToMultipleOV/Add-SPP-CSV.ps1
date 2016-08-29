# =====================================================================================
# Replicate SPP from #1 OneView appliance to Multiple other OV appliances
# Initial Version - HP GSE
# =====================================================================================
param
(
	[parameter(Mandatory = $false)]
    [Alias('a')]
	[string]$Appliance,
	[parameter(Mandatory = $false)]
    [Alias('u')]
	[string]$UserName,
	[parameter(Mandatory = $false)]
    [Alias('p')]
	[string]$Password,
	[parameter(Mandatory = $true)]
    [Alias('i')]
	[string]$ApplianceCsv
)

#$firmwareUri="http://$Appliance/nossl/fwbundles"
$hpOneView=".\HPOneView.200.psm1"


$logDir= "$pwd"
$dateFormat = get-date -format MMddyyyyHHmmss
$addSppLog = $logDir + "\" + "AddSpp" + $dateFormat + ".log"
		
$FirmwareAppliances = Import-csv $ApplianceCsv
Import-Module -DisableNameChecking $hpOneView -WarningAction "SilentlyContinue" -Verbose:$false
Function LogWrite
{
   Param ([string]$logstring,
			[string]$logFile)

   #Add-content $logFile -value $logstring
   $logString >> $logFile
}




LogWrite "SPP Replication" $addSppLog
$arrayJobs=@()
foreach ($Appl in $FirmwareAppliances)
{ 
    $csv_firm = $Appl.firmwareBundleIsoName    
	$csv_ip = $Appl.serverip
	$csv_user = $Appl.username
	$csv_pass = $Appl.password	

    $firmwareUri="/rest/firmware-drivers"
    $url = $firmwareUri+ "/" + $csv_firm
    $FilePath = "$pwd" + "\" + $csv_firm + ".iso"

    
    if (Test-Path $FilePath) 
    { 
        Write-Host "SPP file found in the local machine." 
    } 
    else
    {
        if($Appliance -eq $null -or $UserName -eq $null -or $Password -eq $null){
            Write-Host "Please check the host credentails are nit null"
            exit(0)
        } else{
            Write-Host "Downloading SPP File..."            
            Connect-HPOVMgmt -Appliance $Appliance -User $UserName -Password $Password
            (New-Object System.Net.WebClient).DownloadFile($url, $FilePath)
            Disconnect-HPOVMgmt
        }
    }

    

    if ( $csv_ip -eq $null -or $csv_user -eq $null -or $csv_pass -eq $null)
    {
        Write-Host "Please check the input file"
    } else {

        "DEBUG: Appliance $csv_ip UserName $csv_user Password $csv_pass Filepath $FilePath OneView $oneViewPsmfile">> $addSppLog

        Connect-HPOVMgmt -appliance $csv_ip -user $csv_user -password $csv_pass

        "DEBUG: SessionId for machine $csv_ip is $global:cimgmtSessionId">> $addSppLog        
        
        $breakflag = $false

         

             try{
                $task=Add-HPOVBaseline $FilePath 

                "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") $task" >> $addSppLog
                $task | ConvertTo-Json -depth 99 >> $addSppLog
                "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") Task State: $($task.taskState)" >> $addSppLog
                "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") Resource Uri: $($task.associatedResource.resourceUri)" >> $addSppLog

                if($task.taskState -eq "Error") {
                    "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") Deleting the firmwarebundle located at $($task.associatedResource.resourceUri)" >> $addSppLog
                    Remove-HPOVResource -nameOrUri $task.associatedResource.resourceUri
                }
            } catch [Exception]{
                Write-Host "Check whether the firmware is already installed"
            }

         #while($task.taskState -eq "Error")

        Disconnect-HPOVMgmt    
    }

    
}
Remove-Module HPOneView.200

Write-Host "SPP Replication complete!"


