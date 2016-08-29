##############################################################################
# Name: Utility.psm1 
# Description: Utility functions
# 
# Date: Mar 2016 
##############################################################################

$Global:root               = $pwd
$Global:applXApiVersion    = "/rest/version"
$t = Get-Date -Format dd-MM-yyyy
$Global:LogFilePath = "$Global:root\Logs" +'\Logfile_' +$t +'.'+ "log"



function writeLog 
{
	<#
      Log informational messages.Function will output log messages to assist with debugging
    #>

	Param (
		[parameter (ValueFromPipeline = $true)]
		[System.Object]$message,
		[System.String]$debuglevel = "INFO"
	)
	Begin 
    {
		# Test for existence of log directory
		if(! (Test-Path -Path $Global:LogFilePath))
		{
			New-Item $Global:LogFilePath -ItemType file
		}
	}
	Process 
    {
		$date = Get-Date -format MM:dd:yyyy-HH:mm:ss	
	
		if ($debuglevel -eq "INFO")
		{
			Write-Output "$date INFO: $message" | Out-File $Global:LogFilePath -append
		}
		elseif ($debuglevel -eq "DEBUG")
		{
			Write-Output "$date DEBUG: $message" | Out-File $Global:LogFilePath -append
		}
		elseif ($debuglevel -eq "WARNING")
		{
			Write-Output "$date WARNING: $message" | Out-File $Global:LogFilePath -append
		}
		elseif ($debuglevel -eq "ERROR")
		{
			Write-Output "$date ERROR: $message" | Out-File $Global:LogFilePath -append
		}
	}
}

function connectFusion([string]$ipAddress, [string]$appUname, [string]$appPwd, [string]$authProvider)
{
    <#
	  function Connects to HPOV Appliance.       
    #>
	
	writeLog "FUNCTION BEGIN connectFusion"
    $script:returnCode = Connect-HPOVMgmt -appliance $ipAddress -user $appUname -password $appPwd -authProvider $authProvider  
    return $script:returnCode
    writeLog "FUNCTION END connectFusion"
}

function validateConnection ( $returnCode )
{
    writeLog "FUNCTION BEGIN validateConnection"
    if($returnCode)
    {      
        
	    Write-Host
	    Write-Host "ERROR: Incorrect username or password supplied to $ApplianceIP " -ForegroundColor Yellow -BackgroundColor Black 
	    
    }
    writeLog "FUNCTION END validateConnection"
}

function validate_StartDate($start_Date)
{
    if(!$start_Date)
    { 
        break;
    }
    elseif($start_Date –notmatch $regex )
    {
        write-Host "Plese enter the correct date"
        exit
    }
    
    return $start_Date
   
}

function validate_StartTime($start_time)
 {           
    if(!$start_time)
    {
        [system.string]$start_time="00:00:01"
        break;
    }
    elseif($start_time –notmatch $regex2 )
    {
        write-Host "Plese enter the correct time"
        exit
    }     

    return $start_time
 }
 
 function validate_EndDate($end_Date)
 {
    
    if(!$end_Date)
    { 
        break;
    }
    elseif($end_Date –notmatch $regex )
    {
        write-Host "Plese enter the correct date"
        Exit
    }     
      
    return $end_Date
}
               
 function validate_EndTime($end_time)
 {          
    if(!$end_time)
    {
        [system.string]$end_time="23:59:59"
        break;
    }
    elseif($end_time –notmatch $regex2)
    {
        write-Host "Plese enter the correct time"
        exit
    }
        
    return $end_time
}

function taskCompletionCheck([hashtable]$hashtable, $ErrorFile, $SuccessFile , $state)
{
    <#
      Function to check for the completion of tasks
    #>

    if ($hashtable.Count -ge 1)
    {
        foreach($task in $hashtable.GetEnumerator())
        {
            $taskUri = $task.key
            $taskResourceName = $task.Value

            $taskStatus = Wait-HPOVTaskComplete $taskUri -timeout (New-TimeSpan -Minutes 60)

            if($taskStatus.taskErrors -ne "null")
            {                                
                writeLog $taskStatus.taskErrors.message -debuglevel "ERROR"
                $taskResourceName + "," + $taskStatus.taskErrors.errorCode | Add-Content $ErrorFile -Force
                Write-Host " Failed:"  $taskResourceName "!" "  " -ForegroundColor Red 
            }
            elseif($taskStatus.taskState -eq "Completed" -or $taskStatus.taskState -eq "Running" -or $taskStatus.taskState -eq "Applying" -or $taskStatus.taskState -eq "Starting")
            {
                $resourceName = $taskStatus.associatedResource.resourceName
                writeLog -message " $taskResourceName is $state"
                Write-Host  $taskResourceName "$state!" -ForegroundColor Yellow
                $taskResourceName + "," + $state | Add-Content $SuccessFile -Force 
            }
        }
    }
}

function CreateNewFile($successFile, $ErrorFile)
{
    <#
      Function creates output files for OneViewServerManagementModule.psm1
    #>

    if(! (Test-Path -Path $successFile  -PathType Any))
    {
        New-Item -ItemType File -Path  $successFile
    }
    if(! (Test-Path -Path  $ErrorFile -PathType Any))
    {
        New-Item -ItemType File -Path  $ErrorFile
    }
    Clear-Content -Path  $successFile
    Clear-Content -Path  $ErrorFile
}

function CreateNewGetFile($outputFile)
{
    <#
      Function creates output files for OneViewServerReportsModule.psm1
    #>

    if(! (Test-Path -Path $outputFile  -PathType Any))
    {
        New-Item -ItemType File -Path  $outputFile
    }
    Clear-Content -Path  $outputFile
}



function cleanup{
    try
    {
        $modules= Get-Module 
        $i=0
        if ($returncode -ne "" -or $returncode -ne $null)
        {
            Disconnect-HPOVMgmt
            for($i -eq 0;$i -lt $modules.Name.Length;$i=$i+1)
            {
                if(($modules.Name[$i].SubString(0,1) -ne "M") -and ($modules.Name[$i].SubString(0,1) -ne "I"))
                {
                    Remove-Module $modules.Name[$i]
                }
            }
        }
        exit
    }
    catch
    {
        exit
    }
}