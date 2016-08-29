##############################################################################
# Name: OneViewServerManagementModule.psm1 
# 
# Description: Wrapper functions to achieve oneview server and server profiles
#              functionalities. It uses HPOneView.200.psm1 module to
#              to invoke rest api of oneview
# 
# Date: Mar 2016 
##############################################################################

Import-Module .\Utility.psm1


#-------------------------------------------
#List of all resource URIs:
#-------------------------------------------
$Global:serverhardwareuri                       = "/rest/server-hardware"
$Global:serverProfilesUri                       = "/rest/server-profiles"
$Global:serverProfileTemplateUri                = "/rest/server-profile-templates"
$Global:firmwareBundleUri                       = "/rest/firmware-drivers"
$Global:serverhardwaretypeUri                   = "/rest/server-hardware-types" 
$Global:ethernetNetworksuri                     = "/rest/ethernet-networks" 
$Global:FCNetworksuri                           = "/rest/fc-networks"
$Global:FCoENetworksuri                         = "/rest/fcoe-networks"
$Global:Networkset                              = "/rest/network-sets"
$Global:storageSystemUri                        = "/rest/storage-systems"
$Global:storagePoolUri                          = "/rest/storage-pools"
$Global:StorageVolumeUri                        = "/rest/storage-volumes"
$Global:volumeTemplateUri                       = "/rest/storage-volume-templates"
$Global:bulkEthernetUri                         = "/rest/ethernet-networks/bulk"


#------------------------------------------
#Json Files required :
#------------------------------------------
$Global:root                                    = $PWD
$Global:addServerJson                           = "$Global:root\Input_JSON_files\AddServer.json" 
$Global:powerInputJson                          = "$Global:root\Input_JSON_files\PowerState.json"
$Global:updateServersJson                       = "$Global:root\Input_JSON_files\UpdateServerProfile.json"
$Global:UpdatePowerOff                          = "$Global:root\Input_JSON_files\UpdateServerProfilePowerOff.json"
$Global:Region_US                               = "US"
$Global:Region_EMEA                             = "EMEA"
$Global:Region_APJ                              = "APJ"
$Global:Password                                = $null
$Global:pass_status                             = "PASS"
$Global:fail_status                             = "FAIL"
$Global:CreateServerProfileTemplateJson         = "$Global:root\Input_JSON_files\CreateServerProfileTemplate.json"
$Global:file                                    = "$Global:root\Input_JSON_files\restore_back.json"

#------------------------------------------
#Output Files path :
#------------------------------------------

$Global:UpdateServerProfileStatus               = "$Global:root\Output_File\UpdateServerProfileSuccessStatus"+  "." + $Global:ipAddress
$Global:UpdateServerProfileErrorStatus          = "$Global:root\Output_File\UpdateServerProfileErrorStatus"+  "." + $Global:ipAddress
$Global:CreateProfileErrorStatus                = "$Global:root\Output_File\CreateServerProfileErrorStatus"+  "." + $Global:ipAddress
$Global:CreateProfileAddedStatus                = "$Global:root\Output_File\CreateServerProfileAddedStatus"+  "." + $Global:ipAddress
$Global:PowerStateSuccess                       = "$Global:root\Output_File\PowerStateSuccess"+  "." + $Global:ipAddress
$Global:PowerStateError                         = "$Global:root\Output_File\PowerStateError"+  "." + $Global:ipAddress
$Global:RemoveServersSuccess                    = "$Global:root\Output_File\RemoveServersSuccess"+  "." + $Global:ipAddress
$Global:RemoveServerProfilesSuccess             = "$Global:root\Output_File\RemoveServerProfilesSuccess"+  "." + $Global:ipAddress
$Global:RemoveServerProfileTemplates            = "$Global:root\Output_File\RemoveServerProfileTemplates"+  "." + $Global:ipAddress
$Global:RemoveServerProfileTemplatesSuccess     = "$Global:root\Output_File\RemoveServerProfileTemplatesSuccess"+  "." + $Global:ipAddress
$Global:Create_ServerProfileTemplateSuccess     = "$Global:root\Output_File\Create_ServerProfileTemplateSuccess"+  "." + $Global:ipAddress
$Global:Create_ServerProfileTemplateError       = "$Global:root\Output_File\Create_ServerProfileTemplateError"+  "." + $Global:ipAddress
$Global:RemoveServerProfilesError               = "$Global:root\Output_File\RemoveServerProfilesError"+  "." + $Global:ipAddress
$Global:RemoveServersError                      = "$Global:root\Output_File\RemoveServersError"+  "." + $Global:ipAddress
$Global:RemoveServerProfileTemplatesError       = "$Global:root\Output_File\RemoveServerProfileTemplatesError"+  "." + $Global:ipAddress
$Global:AddEnclosuresStatus                     = "$Global:root\Output_File\AddEnclosuresSuccess"+  "." + $Global:ipAddress
$Global:AddEnclosuresErrorStatus                = "$Global:root\Output_File\AddEnclosuresError"+  "." + $Global:ipAddress
$Global:RemoveEnclosuresSuccess                 = "$Global:root\Output_File\RemoveEnclosuresSuccess"+  "." + $Global:ipAddress
$Global:RemoveEnclosuresError                   = "$Global:root\Output_File\RemoveEnclosuresError"+  "." + $Global:ipAddress
$Global:AddEnclosureGroupSuccess                = "$Global:root\Output_File\AddEnclosureGroupSuccess"+  "." + $Global:ipAddress
$Global:AddEnclosureGroupError                  = "$Global:root\Output_File\AddEnclosureGroupError"+  "." + $Global:ipAddress
$Global:RemoveEnclosureGroupSuccess             = "$Global:root\Output_File\RemoveEnclosureGroupSuccess"+  "." + $Global:ipAddress
$Global:RemoveEnclosureGroupError               = "$Global:root\Output_File\RemoveEnclosureGroupError"+  "." + $Global:ipAddress
$Global:AddLogicalInterconnectGroupsSuccess     = "$Global:root\Output_File\AddLogicalInterconnectGroupsSuccess"+  "." + $Global:ipAddress
$Global:AddLogicalInterconnectGroupsError       = "$Global:root\Output_File\AddLogicalInterconnectGroupsError"+  "." + $Global:ipAddress
$Global:addNetworksJson                         = "$Global:root\Input_JSON_files\AddNetworks.json"
$Global:addNetworksSetJson                      = "$Global:root\Input_JSON_files\AddNetworkSet.json"
$Global:AddNetworksSuccessStatus                = "$Global:root\Output_File\AddNetworksSuccessStatus"+  "." + $Global:ipAddress
$Global:AddNetworksErrorStatus                  = "$Global:root\Output_File\AddNetworksErrorStatus"+  "." + $Global:ipAddress
$Global:AddEthernetNetworksBulkSuccessStaus     = "$Global:root\Output_File\AddEthernetNetworksBulkSuccessStaus"+  "." + $Global:ipAddress
$Global:AddEthernetNetworksBulkErrorStatus      = "$Global:root\Output_File\AddEthernetNetworksBulkErrorStatus"+  "." + $Global:ipAddress
$Global:RemoveNetworksErrorStatus               = "$Global:root\Output_File\RemoveNetworksErrorStatus"+  "." + $Global:ipAddress
$Global:RemoveNetworksSuccessStatus             = "$Global:root\Output_File\RemoveNetworkSuccessStatus"+  "." + $Global:ipAddress
$Global:AddNetworkSetSuccessStatus              = "$Global:root\Output_File\AddNetworkSetSuccessStatus"+  "." + $Global:ipAddress
$Global:AddNetworkSetErrorStatus                = "$Global:root\Output_File\AddNetworkSetErrorStatus"+  "." + $Global:ipAddress
$Global:RemoveNetworkSetSuccessStatus           = "$Global:root\Output_File\RemoveNetworkSetErrorStatus"+  "." + $Global:ipAddress
$Global:RemoveNetworkSetErrorStatus             = "$Global:root\Output_File\RemoveNetworkSetErrorStatus"+  "." + $Global:ipAddress
$Global:AddStorageSystemSuccessStatus           = "$Global:root\Output_File\AddStorageSystemSuccessStatus"+  "." + $Global:ipAddress
$Global:AddStorageSystemErrorStatus             = "$Global:root\Output_File\AddStorageSystemErrorStatus"+  "." + $Global:ipAddress
$Global:AddStoragePoolSuccessStatus             = "$Global:root\Output_File\AddStoragePoolSuccessStatus"+  "." + $Global:ipAddress
$Global:AddStoragePoolErrorStatus               = "$Global:root\Output_File\AddStoragePoolErrorStatus"+  "." + $Global:ipAddress
$Global:RemoveStorageSystemErrorStatus          = "$Global:root\Output_File\RemoveStorageSystemErrorStatus"+  "." + $Global:ipAddress
$Global:RemoveStorageSystemSuccessStatus        = "$Global:root\Output_File\RemoveStorageSystemSuccessStatus"+  "." + $Global:ipAddress
$Global:AddVolumeTemplateSuccessStaus           = "$Global:root\Output_File\AddVolumeTemplateSuccessStaus"+  "." + $Global:ipAddress
$Global:AddVolumeTemplateErrorStatus            = "$Global:root\Output_File\AddVolumeTemplateErrorStatus"+  "." + $Global:ipAddress
$Global:AddVolumeErrorStatus                    = "$Global:root\Output_File\AddVolumeErrorStatus"+  "." + $Global:ipAddress
$Global:AddVolumeSuccessStatus                  = "$Global:root\Output_File\AddVolumeSuccessStatus"+  "." + $Global:ipAddress
$Global:RemoveStoragePoolSuccessStatus          = "$Global:root\Output_File\RemoveRemoveStoragePoolSuccessStatus"+  "." + $Global:ipAddress
$Global:RemoveStoragePoolErrorStatus            = "$Global:root\Output_File\RemoveRemoveStoragePoolErrorStatus"+  "." + $Global:ipAddress
$Global:RemoveVolumeTemplateSuccessStatus       = "$Global:root\Output_File\RemoveVolumeTemplateSuccessStatus"+  "." + $Global:ipAddress
$Global:RemoveVolumeTemplateErrorStatus         = "$Global:root\Output_File\RemoveVolumeTemplateErrorStatus"+  "." + $Global:ipAddress
$Global:RemoveStorageVolumeSuccessStatus        = "$Global:root\Output_File\RemoveStorageVolumeSuccessStatus"+  "." + $Global:ipAddress
$Global:RemoveStorageVolumeErrorStatus          = "$Global:root\Output_File\RemoveStorageVolumeErrorStatus"+  "." + $Global:ipAddress
                   
function loopback($return_json)
{
     $Global:serverHardwareUri = $null

     if ($return_json.members.name -contains $csvServerName)
     {
        foreach ($name in $return_json.members.getEnumerator())
        {
            if (($name.name -eq $csvServerName) -and ($name.state -eq "NoProfileApplied"))
            {

                $Global:serverHardwareUri = $name.uri
            }
            
            elseif (($name.name -eq $csvServerName) -and ($name.state -eq "ProfileApplied")) 
            {
                Write-Host " $csvServerName Hardware already used"
                writeLog " $csvServerName Hardware already used"
                $csvServerProfileName + "," + $csvServerName+ " : " +" Server Hardware already used" | Add-Content $Global:CreateProfileErrorStatus -Force         
            }
        }
    }
    elseif($return_json.members.name -notcontains $csvServerName)
    {
        Write-Host "Error: $csvServerName Server Hardware doesnot exists" -ForegroundColor Red
        writeLog "Error:  $csvServerName Server Hardware doesnot exists"
        $csvServerProfileName + "," +  $csvServerName + " : " +" Server Hardware doesnot exists" | Add-Content $Global:CreateProfileErrorStatus -Force
    }
    
    return
}                      

function AddServer
{
    <#
        To Add servers into OneView.         
        Takes list of iLOs as inputs
        Successfully addded servers are returned in success file
        Failed to add iLOs are writted error file
    #>
    Param(             
             
        [parameter(Mandatory = $true, HelpMessage = "Enter the IP ")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ApplianceIP,

        [parameter(Mandatory = $true, HelpMessage = "Enter the username")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ApplianceUserName,


        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$iLOAddressList,    
        

        [parameter(Mandatory = $true, HelpMessage = "Enter the iLO username ")]
        [ValidateNotNullOrEmpty()]
        [System.String]$iLOUsername,

        [parameter(Mandatory = $true, HelpMessage = "Enter the iLO username ")]
        [ValidateNotNullOrEmpty()]
        [String]$AuthProvider= "LOCAL",                

        [parameter(Mandatory = $false, HelpMessage = "Enter the iLO password ")]
        [ValidateNotNullOrEmpty()]
        $iLOPassword,

        [parameter(HelpMessage = "Enter the output file ")]
        [string]$outputFile,

        [parameter(HelpMessage = "Enter the config state either Managed or Monitored  file ")]
        [string]$configurationState = "Managed"

       )

    Process 
    {

            #validate inputs

            if ($iLOAddressList -eq "" -or $iLOAddressList -eq $null) {
                
                Write-Host "ERROR: iLO input empty" -ForegroundColor DarkRed
                writeLog "ERROR: iLO input empty"
                return
            }

            if ($configurationState -ne "Managed" -and $configurationState -ne "Monitored") {
                
                Write-Host "ERROR: Configuration state : $configurationState  is invlid please enter either 'Managed' or 'Monitored'" -ForegroundColor DarkRed
                writeLog "ERROR: Configuration state is invlid please enter either 'Managed' or 'Monitored'"
                return
            }


            if ($Global:Password -eq $null){
               [System.Security.SecureString]$tempPassword = Read-Host "Enter the OneView appliance Password for $Username@$ApplianceIP " -AsSecureString
                $Global:Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($tempPassword))            
            } 
  
            #connects to the appliance
            writeLog -message "FUNCTION BEGIN : ADD SERVERS"

            $AddServerErrorStatus          = "$Global:root\Output_File\AddServerErrorStatus" 
            $AddServerSuccessStatus        = "$Global:root\Output_File\AddServerSuccessStatus"
            if ($outputfile -eq $null -or $outputFile -eq "") { 
                $outputFile = $AddServerSuccessStatus +  "." + $ApplianceIP
            }
            $AddServerErrorStatus = $AddServerErrorStatus +  "." + $ApplianceIP
            
            if(! (Test-Path -Path $AddServerErrorStatus -PathType Any))
            {
                New-Item -ItemType File -Path $AddServerErrorStatus
            }

            Clear-Content -Path $AddServerErrorStatus

            if(! (Test-Path -Path $outputFile -PathType Any))
            {
                New-Item -ItemType File -Path $outputFile
                
            }
                
            Clear-Content -Path $outputFile
                        

            $returnCode = connectFusion $ApplianceIP $ApplianceUserName $Global:Password $AuthProvider
            validateConnection
            
                
            #For success file
            $pass_file_header = "iLO_IP,iLO_hostname,iLO_Hostname_Short,Status,Remarks"
            #$header | Add-Content $AddServerSuccessStatus
            
            $pass_file_header | Add-Content $outputFile

            #For fail file
            $fail_file_headers = "iLO_Hostname,Error_status,Message"
            $fail_file_headers | Add-Content $AddServerErrorStatus       
            
            if ( $iLOAddressList )
            {
               #TODO - delete it later
                        
               if ($ilo_password -eq $null -or $ilo_password -eq "") {
                   [System.Security.SecureString] $ilo_password = Read-Host "Enter the one time iLO password for servers to be added:" -AsSecureString
                   $iLOPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ilo_password))
               }
            
               $inputData = Import-csv $iLOAddressList
               foreach ($input in $inputData )
               {   
               
                    #add servers whose status = "FAIL"
                    #skip the PASS servers
                    $inputStatus = $input.Status

                    if ($input.Status -ne $Global:pass_status) 
                    {
                                                                
                        #TODO - change the variable names
                        #Note: this condition works only if input file has short FQDN.
                        #if input file has IP address, when you add IP in oneview, that IP is converted into short FQDN
                        # and  OneView shows short FQDN as resource name on server-hardware page even though user
                        # add iLO with IP.
                        #TODO: handle this later if you are comparing IP address with short FQDN       

                        if ($input.iLO_hostname -eq "" -or $input.iLO_hostname -eq $null)
                        {
                            $csv_hostname = $input.iLO_IP
                        }else
                        {
                            $csv_hostname = $input.iLO_hostname
                        }
                        
                        $csv_username = $iLOUsername
                        $csv_password = $iLOPassword
                        $csv_configurationState = $configurationState

                        #Debug
                        #Write-Host "input line : $input"

                        if ($csv_configurationState -eq "Managed" -or $csv_configurationState -eq "managed") {

                            $csv_licensingIntent = "OneView"
                            #Write-Host "Adding servers in Managed mode"

                        }elseif ($csv_configurationState -eq "Monitored" -or $csv_configurationState -eq "monitored" ) {

                            $csv_licensingIntent = "OneViewStandard"
                            #Write-Host "Adding servers in Monited mode"
                        }

                        if ($csv_hostname -eq $null -or $csv_username -eq $null -or $csv_password -eq $null -or $csv_licensingIntent -eq $null -or $csv_configurationState -eq $null )
                        {
                            Write-Host " Please verify the Inventory File "
                            writeLog  " Please verify the Inventory File "
                            exit
                        }
                                       
                        #Create POST request JSON body
                        $path = Get-Content $Global:addServerJson -Raw | convertFrom-json 
                        $path | add-member -NotePropertyName hostname  -NotePropertyValue $csv_hostname
                        $path | add-member -NotePropertyName username -NotePropertyValue $csv_username
                        $path | add-member -NotePropertyName password -NotePropertyValue $csv_password
                        $path | add-member -NotePropertyName licensingIntent -NotePropertyValue $csv_licensingIntent
                        $path | add-member -NotePropertyName configurationState -NotePropertyValue $csv_configurationState
                         
                        #Debug
                        #Write-Host " POST request body for adding server: $path"
                        
                        $response = Send-HPOVRequest -uri $Global:serverhardwareuri POST $path 
                        $response_uri = $response.uri
                    
                        #Debug
                        #Write-Host " response object from add server : $response "
                        $resource_name = $csv_hostname
                        
                        if ($response_uri -ne $null)
                        {
                            $taskList += [System.Array]$response_uri
                            $response_name_list += [System.Array]$resource_name
                        }                    
                    }        
               }

               #below blocks Checks for the task completion before returning
               $statusCheck = $false

               $hashtable = @{}
               for($i = 0 ; $i -le ($taskList.count - 1) ; $i++)
               {
                    $hashtable.Add($response_name_list[$i],$taskList[$i]) 
               }
           
                
               #Check for the tasks 
               if ($taskList.Count -ge 1)
               {
                    $statusCheck = $true
                    
                    #TODO - Optimize this code
                    foreach($task in $taskList.GetEnumerator())
                    {
                        foreach($item in $hashtable.GetEnumerator())
                        {
                            if($task -eq $item.Value)
                            {
                                
                                $iLO_Address = $item.Name
                                $position = $iLO_Address.LastIndexOf(".")
                                $last_part = $iLO_Address.SubString($position + 1 )
                                
                                if ([int]$last_part -is [int] ) {
                                
                                    #Format: iLO_IP,,,
                                    $combined_iLO_name = $iLO_Address + "," + ","

                                }else{
                                    #Format: ,iLO_Hostname ,
                                    $combined_iLO_name =  "," + $iLO_Address + ","
                                
                                }   

                                #Prakash: Max wait for 3 minutes
                                $taskStatus = Wait-HPOVTaskComplete $task -timeout (New-TimeSpan -Minutes 10)
                                $resource_name = $taskStatus.associatedResource.resourceName
    
                                if($taskStatus.taskErrors -ne "null" -and $taskStatus.taskState -eq "Warning")
                                {
                                    #$hash.Name + ",  " + "Added" | Add-Content $AddServerSuccessStatus -Force
                                    
                                    $combined_iLO_name + ",  " + $Global:pass_status  | Add-Content $outputFile -Force

                                    writeLog -message $iLO_Address "is added!"
                                    Write-Host $iLO_Address "added!" -ForegroundColor Yellow
                                }

                                if($taskStatus.taskErrors -ne "null" -and $taskStatus.taskState -eq "Error")
                                {   
                                    if($taskStatus.taskErrors.message -contains "Unable to determine the hardware configuration for " +"`'"+$iLO_Address+"`'.")
                                    {  
                                        writeLog $iLO_Address -debuglevel "ERROR"                       
                                        
                                        $iLO_Address + ", " + "NON_iLO" +","+ $taskStatus.taskErrors.message | Add-Content $AddServerErrorStatus -Force 
                                        $combined_iLO_name + "," + $Global:fail_status  | Add-Content $outputFile -Force
                                        
                                        writeLog -message $taskStatus.taskErrors.message -debuglevel "ERROR"
                                        Write-Host $iLO_Address  "Failed!" 
                                    }
                                    elseif($taskStatus.taskErrors.message -match "Unable to discover the server hardware.")
                                    {
                                        writeLog $iLO_Address -debuglevel "ERROR" 
                                        
                                        $msg = $taskStatus.taskErrors.message
                                        $message = $msg -replace "\s"," "
                                        
                                        $iLO_Address + ", " + "WRONG_CREDENTIALS"+","+ $message | Add-Content $AddServerErrorStatus -Force 
                                        $combined_iLO_name + "," + $Global:fail_status  | Add-Content $outputFile -Force
                                        
                                        writeLog -message $message -debuglevel "ERROR"  
                                        Write-Host $hash.Name  "Failed!" 
                                    }
                                    #TODO - test this condition
                                    elseif($taskStatus.taskErrors.message -contains "The server hardware has already been added")
                                    {
                                        writeLog $iLO_Address -debuglevel "ERROR" 
                                        
                                        $msg = $taskStatus.taskErrors.message
                                        $message = $msg -replace "\s"," "
                                        
                                        $iLO_Address + ", " + "ALREADY_EXISTS"+","+ $message | Add-Content $AddServerErrorStatus -Force 
                                        $combined_iLO_name + ",  " + $Global:fail_status  | Add-Content $outputFile -Force
                                        
                                        writeLog -message $message -debuglevel "ERROR"  
                                        
                                        Write-Host $iLO_Address  "Failed!" 

                                        Write-Host $iLO_Address "Already present in the appliance"
                                        writeLog $iLO_Address "Already present in the appliance" 
                                    }
                                    else
                                    {
                                        writeLog $taskStatus.taskErrors.message -debuglevel "ERROR"
                                        
                                        $iLO_Address + ", " +"OTHERS"+","+ $taskStatus.taskErrors.message | Add-Content $AddServerErrorStatus -Force 
                                        $combined_iLO_name + ", " + $Global:fail_status  | Add-Content $outputFile -Force

                                        writeLog -message $taskStatus.taskErrors.message -debuglevel "ERROR"
                                        Write-Host $iLO_Address  "Failed!" 
                                    }  
                                } 
                    
                                if($taskresponse.taskState -eq "Running" -or $taskresponse.taskState -eq "Completed")
                                {
                                    #$hash.Name + ",  " + "Added" | Add-Content $AddServerSuccessStatus -Append
                                    $combined_iLO_name + ", " + $Global:pass_status  | Add-Content $outputFile -Force

                                    writeLog -message $iLO_Address "added!" 
                                    Write-Host $iLO_Address "added!" -ForegroundColor Yellow
                                } 
                            }
                        } 
                    }
                } 

                
                #Write-Host "View the success reports at: $AddServerSuccessStatus"
                Write-Host ""
                Write-Host "View the success reports at $outputFile"
                Write-Host ""
                Write-Host "View the error reports at: $AddServerErrorStatus"

            } 
         Disconnect-HPOVMgmt
         writeLog "FUNCTION END : ADD SERVERS"           
    }            
} 

function CreateServerProfile 
{
    <#
      Create server profile
    #>

    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the appliance DNS name or IP")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ProfileInputs,


        [parameter(Mandatory = $true, HelpMessage = "Enter the X-API Version")]
        [ValidateNotNullOrEmpty()]
        [System.String]$version
        
  
    )
       
    Process 
    {
        writeLog "FUNCTION BEGIN : CREATE SERVER PROFILES"

        CreateNewFile $Global:CreateProfileAddedStatus $Global:CreateProfileErrorStatus
                   
        $state = "Created"
        $header = "Server_Profile_Name,Status"
        
        #For fail file
        $header | Add-Content $Global:CreateProfileErrorStatus
        #For success file
        $header | Add-Content $Global:CreateProfileAddedStatus           
                                 
        $return_json = Send-HPOVRequest -uri $Global:serverhardwareuri GET 
        $hashtable = @{}
                   
        if ( $ProfileInputs )
        {
            Write-Host "Creating Server Profiles... " -ForegroundColor Yellow
            writeLog "Creating Server Profiles... "
            $inputData = Import-csv $ProfileInputs
            
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                
                $ServerName = $input.hostname
                $ServerProfileName = $input.serverprofile_name
                $ServerProfileTemplateName = $input.sptname
                
                $csvServerName = $ServerName.Trim() 
                $csvServerProfileName = $ServerProfileName.Trim() 
                $csvServerProfileTemplateName = $ServerProfileTemplateName.Trim() 

                if ( $csvServerName -eq $null -or   $csvServerProfileName -eq $null -or $csvServerProfileTemplateName-eq $null )
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                
                loopback $return_json 

                $serverProfileTemplate_json = Send-HPOVRequest -uri $Global:serverProfileTemplateUri GET 

                if($serverProfileTemplate_json.members.name -contains $csvServerProfileTemplateName)
                {                      
                    foreach ($sptName in $serverProfileTemplate_json.members.getEnumerator())
                    {                       
                        if (($sptName.name -eq $csvServerProfileTemplateName) -and ($serverHardwareuri -ne $null))
                        {    
                            #Create POST request JSON body
                            $sptJson = $sptName             
                            $sptJson| add-member -NotePropertyName serverHardwareUri -NotePropertyValue $Global:serverHardwareUri
                            $sptJson | Add-Member -NotePropertyName serverProfileTemplateUri -NotePropertyValue $sptJson.uri 
                            $sptJson.name = $csvServerProfileName
                            if($version -eq "200")
                            {
                                $sptJson.type = "ServerProfileV5"
                            }
                            elseif($version -eq "300")
                            {
                                $sptJson.type = "ServerProfileV6"
                            }
                            $serverProfileTemplatejson = $sptJson | Select-Object -Property * -ExcludeProperty serverProfileDescription,category,created,modified,status,state,eTag,uri 
                            #operation to create profiles using template.
                            $response = Send-HPOVRequest -uri $Global:serverProfilesUri POST $serverProfileTemplatejson 
                            $responseUri = $response.uri
                            $resourceName = $csvServerProfileName
                        
                            if ($responseUri -ne $null)
                            {
                                $hashtable.Add( $responseUri,$resourceName)
                            }            
                        } 
                    }
                   
                }
                elseif($serverProfileTemplate_json.members.name -notcontains $csvServerProfileTemplateName)
                {
                    Write-Host "$csvServerProfileTemplateName  is not present" -ForegroundColor Red
                    writeLog "$csvServerProfileTemplateName  is not present"
                }
            }
            taskCompletionCheck $hashtable $Global:CreateProfileErrorStatus $Global:CreateProfileAddedStatus $state
            
            Write-Host "View the error report in $Global:CreateProfileErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:CreateProfileAddedStatus"
            writeLog "View the error report in $Global:CreateProfileErrorStatus" 
            writeLog "View the success report in $Global:CreateProfileAddedStatus" 
        } 
        writeLog "FUNCTION END : CREATE SERVER PROFILES"
    }    
}

function PowerState
{
    <#
      Function to power OFF or ON for a given list of servers managed by OneView       
    #>

    Param
    (               
        [parameter(Mandatory = $true, HelpMessage = "Enter the inventory list")]
        [ValidateNotNullOrEmpty()]
        [System.String]$PowerInput      

    )
       
    Process 
    {
        writeLog "FUNCTION BEGIN : POWER STATE"
        CreateNewFile $Global:PowerStateSuccess $Global:PowerStateError
        $header = "Server_Name,Power_State"

        #For success file
        $header | Add-Content $Global:PowerStateSuccess
        $header = "Server_Name,State"
        #For fail file
        $header | Add-Content $Global:PowerStateError
                                             
        $ret_json = Send-HPOVRequest -uri $Global:serverhardwareuri GET

        $hashtable1 = @{}
        $hashtable2 = @{}
        Write-Host "Changing Power States of the servers... " -ForegroundColor Yellow
        writeLog "Changing Power States of the servers... "
        
        if ($PowerInput)
        {
            $inputFile = Import-csv $PowerInput    
            foreach ($input in $inputFile)
            {
                #to retrive all the attributes from the input file.

                $ServerName = $input.hostname
                $csvServerName = $ServerName.Trim()
                $PowerState = $input.power_state
                $csvPowerState = $PowerState.Trim()

                if ($csvServerName -eq $null -or $csvPowerState -eq $null)
                {
                    Write-Host " Please verify the Inventory File. "
                    writeLog " Please verify the Inventory File. "
                    exit    
                }
                   
                if($ret_json.members.name -contains $csvServerName)
                {  
                    foreach($name in $ret_json.members.getEnumerator())
                    {   
                        if($name.name -eq $csvServerName)
                        {
                            if($name.powerState -eq $csvPowerState)
                            {
                                Write-Host $csvServerName "Same PowerState"
                                writeLog "$csvServerName : You have selected the same state as server's current state"
                                $csvServerName+ "," + "is already $csvPowerState"  | Add-Content $Global:PowerStateError -force
                            }
                            else
                            {
                                #Create PUT request JSON body
                                $Global:serverHarwareUri = $name.uri
                                $path = Get-Content $Global:powerInputJson -Raw | convertFrom-json 
                                $path | add-member -NotePropertyName powerState -NotePropertyValue $csvPowerState
                                $response = Send-HPOVRequest -uri $Global:serverHarwareUri/powerState PUT $path
                                $response_uri = $response.uri
                                $resource_name =  $csvServerName
                                $resource_state = $csvPowerState
                                            
                                if ($response_uri -ne $null)
                                {
                                    $hashtable1.Add($response_uri,$resource_name)   
                                    $hashtable2.Add($response_uri,$resource_state) 
                                }
                            }
                        }
                    }
                }
                else
                {
                    Write-Host "$csvServerName doesnot exists!" -ForegroundColor Red
                    writeLog "$csvServerName doesnot exists!"
                    $csvServerName+","+"doesnot exists" | Add-Content $Global:PowerStateError -Force 
                }
            }
            #below blocks Checks for the task completion before returning 
            if ($hashtable1.Count -ge 1)
            {                                       
                foreach($hash1 in $hashtable1.GetEnumerator())
                {
                    foreach($hash2 in $hashtable2.GetEnumerator())
                    {
                        #Check for the tasks 
                        if($hash1.Key -eq $hash2.Key)
                        {
                            $task = $hash1.Key
                            $name = $hash1.Value
                            $state = $hash2.Value
                            $taskStatus = Wait-HPOVTaskComplete $task -timeout (New-TimeSpan -Minutes 10)
                            writeLog -message "$name is $state" -debuglevel "INFO" 
                            Write-Host $name "is turned"  $state
                            $name+ "," + $state | Add-Content $Global:PowerStateSuccess -Force
                        }
                    }                        
                }         
            }
            Write-Host "View the reports in $Global:PowerStateSuccess"
            Write-Host "View the Error reports in $Global:PowerStateError" -ForegroundColor Red  
            writeLog "View the reports in $Global:PowerStateSuccess"
            writeLog "View the Error reports in $Global:PowerStateError"          
        }     
        writeLog "FUNCTION END : POWER STATE"
    }
}

function UpdateServerProfile
{
    <#
      Update the server-profile         
    #>

    Param
    (           
             
        [parameter(Mandatory = $true, HelpMessage = "Enter the inventory file")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ServerProfileTemplatesList

    )
       
    Process 
    {
        writeLog "FUNCTION BEGIN : UPDATE SERVER PROFILES"
            
        CreateNewFile $Global:UpdateServerProfileStatus $Global:UpdateServerProfileErrorStatus
                        
        $state = "Updated"
        $header = "Server_Profile,Server_Profile_Template,Status"

        #for success file
        $header | Add-Content $Global:UpdateServerProfileStatus
        #for fail file 
        $header | Add-Content $UpdateServerProfileErrorStatus
                                                         
        $Global:serverProfile = Send-HPOVRequest -uri $Global:serverProfilesUri GET
        $Global:serverProfileTemplate = Send-HPOVRequest -uri $Global:serverProfileTemplateUri GET
            
        $hashtable = @{}            
        if ( $ServerProfileTemplatesList )
        {
            Write-Host "Updating Server Profiles..." -ForegroundColor Yellow 
            writeLog "Updating Server Profiles..."
            $inputFile = Import-csv $ServerProfileTemplatesList   
            foreach ($input in $inputFile)
            {
                $ServerProfileTemplate = $input.serverProfileTemplate
                $csvServerProfileTemplate = $ServerProfileTemplate.Trim()

                if ($csvServerProfileTemplate -eq $null)
                {
                    Write-Host " Please verify the Inventory File. "
                    writeLog " Please verify the Inventory File. "
                    exit    
                }            
                if($serverProfileTemplate.members.name -contains $csvServerProfileTemplate)
                {
                    foreach($serverprofile in $Global:serverProfile.members.GetEnumerator())
                    {
                        foreach($spt in $Global:serverProfileTemplate.members.GetEnumerator())
                        {
                            if ($serverProfile.templateCompliance -eq "NonCompliant" -and $serverprofile.serverProfileTemplateUri -eq $spt.uri -and $spt.name -eq $csvServerProfileTemplate)
                            {
                                #Create PATCH request JSON body
                                $serverProfileUri = $serverProfile.uri
                                $inputData = Get-Content $Global:updateServersJson -Raw | ConvertFrom-Json 
                                $inputData = $inputData | ConvertTo-Json -Depth 99
                                $inputData = "[" + $inputData + "]"
                                $response = Send-HPOVRequest -uri $serverProfileUri PATCH -json $inputData
                                $responseuri = $response.uri
                                $resourcename = $serverprofile.name
                           
                                if ($responseuri -ne $null)
                                {
                                    $hashtable.Add($responseuri, $resourcename)
                                }         
                            }
                            elseif($serverProfile.templateCompliance -eq "Compliant" -and $serverProfile.serverProfileTemplateUri -eq $spt.uri -and $spt.name -eq $csvServerProfileTemplate)
                            {
                                Write-Host "$csvServerProfileTemplate is already Consistent "
                                writeLog "$csvServerProfileTemplate is already Consistent "
                                $csvServerProfileTemplate + ", " + "Already Consistent" | Add-Content $Global:UpdateServerProfileErrorStatus -Force
                            }
                        }   
                    }
                }
                else
                {
                    Write-Host "$csvServerProfileTemplate  is not present in the appliance" -ForegroundColor Red 
                    writeLog "$csvServerProfileTemplate  is not present in the appliance"
                }
            }
            taskCompletionCheck $hashtable $Global:UpdateServerProfileErrorStatus $Global:UpdateServerProfileStatus $state

            Write-Host "View the reports in $Global:UpdateServerProfileStatus"
            Write-Host "View the Error reports in $Global:UpdateServerProfileErrorStatus" -ForegroundColor Red   
            writeLog "View the reports in $Global:UpdateServerProfileStatus"
            writeLog "View the Error reports in $Global:UpdateServerProfileErrorStatus"  
       }
       writeLog "FUNCTION END : UPDATE SERVER PROFILES"
    }
}

function Remove-Servers
{
    <#
      Function to remove servers hardware in the appliance .
    #> 
    
    Param
    (             
             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ServerNamesInput 
    )

    Process 
    {
        writeLog "FUNCTION BEGIN : REMOVE-SERVERS"
        CreateNewFile $Global:RemoveServersSuccess $Global:RemoveServersError
        $state = "Removed"
        $header = "Server_Hardware,Status"
        
        #for success file
        $header | Add-Content $Global:RemoveServersSuccess
        #for fail file
        $header | Add-Content $Global:RemoveServersError
                              
        $Global:serverHardware = Send-HPOVRequest -uri $Global:serverhardwareuri GET 
        $Global:serverProfiles = Send-HPOVRequest -uri $Global:serverProfilesUri GET
        $hashtable = @{}               
        if ($ServerNamesInput )
        {
            Write-Host "Deleting in Progress ... "  -ForegroundColor Yellow
            writeLog "Deleting in Progress ... " 
            $inputData = Import-csv $ServerNamesInput
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
               
                $csv_hw = $input.iLO_hostname        
                if ( $csv_hw -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                if($Global:serverHardware.members.name -contains $csv_hw)
                {
                    foreach ($del in $Global:serverHardware.members.GetEnumerator() )
                    {
                        if($del.name -eq $csv_hw -and $del.state -eq "NoProfileApplied")
                        {
                            #invokes library function to remove the resource
                            $task = Remove-HPOVResource -nameOruri $del.uri -force
                            $response_uri = $task.uri
                            if ($response_uri -ne $null)
                            {
                                $hashtable.Add($response_uri,$csv_hw)
                            }
                        } 
                        elseif($del.name -eq $csv_hw -and $del.state -eq "ProfileApplied")
                        {
                            foreach($sp in $Global:serverProfiles.members.GetEnumerator())
                            {
                                if($sp.serverHardwareUri -eq $del.uri)
                                {
                                    Write-Host "WARNING" : $del.name is used by $sp.name -ForegroundColor Red
                                    writeLog "$del.name is used by $sp.name" -debuglevel "WARNING"
                                    $hwname = $del.name
                                    $spname = $sp.name
                                    writeLog -message "FAILED TO REMOVE $hwname : $hwname is used by $spname server-profile" -debuglevel "WARNING"
                                    $del.name + "," + "Failed to remove :"+ " "+ $del.name + " " +"is used by"+ " " +$sp.name+" " + "server-profile" | Add-Content $Global:RemoveServersError -Force
                                }
                            }
                        }
                        elseif($del.name -eq $csv_hw)
                        {
                            #invokes library function to remove the resource
                            $task = Remove-HPOVResource -nameOruri $del.uri -force:$true
                            $response_uri = $task.uri
                            if ($response_uri -ne $null)
                            {
                                $hashtable.Add($response_uri,$csv_hw)
                            }       
                        }
                    }
                }
                else
                {
                    Write-Host " $csv_hw does not exists" -ForegroundColor Red
                    $csv_hw + "," + "does not exists" | Add-Content $Global:RemoveServersError  -Force 
                    writeLog " $csv_hw does not exists"
                }     
            }          
            
            taskCompletionCheck $hashtable $Global:RemoveServersError $Global:RemoveServersSuccess $state

            Write-Host "View the report in $Global:RemoveServersSuccess"
            writeLog "View the report in $Global:RemoveServersSuccess"
            Write-Host "View the report in $Global:RemoveServersError" -ForegroundColor Red
            writeLog "View the report in $Global:RemoveServersError"
        }
        writeLog "FUNCTION END : REMOVE-SERVERS"
    }
}

function Remove-serverProfileTemplate
{
    <#
      Removes the server profile templates present in the appliance.
    #>
  
    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ServerProfileTemplatesNamesInput     

    )

    Process 
    {
        writeLog "FUNCTION BEGIN : REMOVE-SERVER PROFILE TEMPLATES"
        CreateNewFile $Global:RemoveServerProfileTemplatesSuccess $Global:RemoveServerProfileTemplatesError
        $state = "Removed"
        $header = "Server_Profile_Template,Status"
        
        #for fail file
        $header | Add-Content $Global:RemoveServerProfileTemplatesError
        #for success file
        $header | Add-Content $Global:RemoveServerProfileTemplatesSuccess
        
        $Global:serverProfileTemplate = Send-HPOVRequest -uri $Global:serverProfileTemplateUri GET
        $Global:server_profile = Send-HPOVRequest -uri $Global:serverProfilesUri GET
        $hashtable = @{}
        if ($ServerProfileTemplatesNamesInput)
        {
            Write-Host "Deleting in Progress ... " -ForegroundColor Yellow
            writeLog "Deleting in Progress ... "
            $inputData = Import-csv $ServerProfileTemplatesNamesInput
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                $csv_spt = $input.server_profile_Template
                if ( $csv_spt -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                if($Global:serverProfileTemplate.members.name -contains $csv_spt)
                {
                    foreach($spt in $Global:serverProfileTemplate.members.GetEnumerator())
                    {
                       if($spt.name -eq $csv_spt)
                       {
                           #invoking library function to remove resource
                           $task = Remove-HPOVResource -nameOruri $spt.uri -force
                           $response_uri = $task.uri
                           if ($response_uri -ne $null)
                           {
                               $hashtable.Add($response_uri,$csv_spt)
                           }                       
                       }
                   }
               }
               else
               {
                   Write-Host " $csv_spt does not exists" -ForegroundColor Red
                   $csv_spt + "," + "does not exists" | Add-Content $Global:RemoveServerProfileTemplatesError  -Force "true"
                   writeLog " $csv_spt does not exists"
               }
           }
           
           taskCompletionCheck $hashtable $Global:RemoveServerProfileTemplatesError $Global:RemoveServerProfileTemplatesSuccess $state

           Write-Host "View the report in $Global:RemoveServerProfileTemplatesError" -ForegroundColor Red
           writeLog "View the report in $Global:RemoveServerProfileTemplatesError"
           Write-Host "View the report in $Global:RemoveServerProfileTemplatesSuccess"
           writeLog "View the report in $Global:RemoveServerProfileTemplatesSuccess"
       }
       writeLog "FUNCTION END : REMOVE-SERVER PROFILE TEMPLATES"
   }
}

function Remove-serverProfiles
{
    <#
      To remove server profiles .
    #>
  
    Param
    (       
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ServerProfileNamesInput     
    )

    Process 
    {
        writeLog "FUNCTION BEGIN : REMOVE-SERVER PROFILES"
        CreateNewFile $Global:RemoveServerProfilesSuccess $Global:RemoveServerProfilesError
        $state = "Removed"
        $header = "Server_Profile,Status"
        
        #for success file
        $header | Add-Content $Global:RemoveServerProfilesSuccess
        #for fail file
        $header | Add-Content $Global:RemoveServerProfilesError 

        $Global:serverProfiles = Send-HPOVRequest -uri $Global:serverProfilesUri GET
        $hashtable = @{}
        if ($ServerProfileNamesInput)
        {
            Write-Host "Deleting in Progress ... " -ForegroundColor Yellow
            writeLog "Deleting in Progress ... "
            $inputData = Import-csv $ServerProfileNamesInput
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                $csv_sp = $input.Server_Profiles
                if ( $csv_sp -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }              
                if($Global:serverProfiles.members.name -contains $csv_sp)
                {
                    foreach($sp in $Global:serverProfiles.members.GetEnumerator())
                    {
                        if($sp.name -eq $csv_sp)
                        {
                        $task = Remove-HPOVResource -nameOruri $sp.uri -force 
                        $response_uri = $task.uri 
                        if ($response_uri -ne $null)
                        {
                            $hashtable.Add($response_uri,$csv_sp)
                        }
                    } 
                }
            }
            else
            {
                Write-Host "$csv_sp does not exists" -ForegroundColor Red
                $csv_spt + "," + "does not exists" | Add-Content $Global:RemoveServerProfilesError  -Force
                writeLog "$csv_sp does not exists"
            }
        }
        
        taskCompletionCheck $hashtable $Global:RemoveServerProfilesError $Global:RemoveServerProfilesSuccess $state
               
        Write-Host "View the error report in $Global:RemoveServerProfilesError" -ForegroundColor Red
        writeLog "View the error report in $Global:RemoveServerProfilesError"
        Write-Host "View the success report in $Global:RemoveServerProfilesSuccess" 
        writeLog "View the success report in $Global:RemoveServerProfilesSuccess"  
     }
     writeLog "FUNCTION END : REMOVE-SERVER PROFILES"
   }
} 

function GetServerCount
{
    <#
      This function helps to  get the server count
      from the oneview appliance and 
      add the necessary servers to the appliance
    #>
   
    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the IP ")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ApplianceIP,

        [parameter(Mandatory = $true, HelpMessage = "Enter the username")]
        [ValidateNotNullOrEmpty()]
        [System.String]$UserName

    )

    Process 
    {
        if ($Global:Password -eq $null)
        {
            [System.Security.SecureString]$tempPassword = Read-Host "Enter onetime OneView appliance Password for $Username " -AsSecureString
            $Global:Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($tempPassword))            
        } 
        #connects to the appliance
        writeLog -message "FUNCTION BEGIN : GetServerCount:"

        $returnCode = connectFusion $ApplianceIP $UserName $Global:Password $Global:authProvider
        validateConnection

        $serverObject = Send-HPOVRequest -uri $Global:serverhardwareuri GET  
        $serverCount = $serverObject.members.count 
        
        Write-Host "servers count: $serverCount " 
        writeLog "servers count: $serverCount "
            
        Disconnect-HPOVMgmt
        
        writeLog "FUNCTION END : GetServerCount"           
        return $serverObject.members.count
    }            
}  

function Create_ServerProfileTemplate
{
    <#
      Creates the server profile template through input as json file 
    #>
  
    Param
    (       
        [parameter(Mandatory = $true, HelpMessage = "Enter the base template name")]
        [ValidateNotNullOrEmpty()]
        [System.String]$BasetemplateName,

        [parameter(Mandatory = $true, HelpMessage = "Enter the list of template names to be created")]
        [ValidateNotNullOrEmpty()]
        [array]$ProfileTemplateInputs,

        [parameter(Mandatory = $true, HelpMessage = "Enter the list of target ip addrress")]
        [ValidateNotNullOrEmpty()]
        [array]$TargetIpAddresses
    )

    Process 
    {
        writeLog "FUNCTION BEGIN : CREATE-SERVER_PROFILE_TEMPLATE"
        CreateNewFile $Global:Create_ServerProfileTemplateSuccess $Global:Create_ServerProfileTemplateError
        
        $state = "Created"
        $header = "Server_Profile_Template,Appliance,Status"
        try
        {
            #for success file
            $header | Add-Content $Global:Create_ServerProfileTemplateSuccess
            #for fail file 
            $header | Add-Content $Global:Create_ServerProfileTemplateError
 
            $serverProfileTemplate = Send-HPOVRequest -uri $Global:serverProfileTemplateUri GET 
            if($serverProfileTemplate.members.name -contains $BasetemplateName)
            {
                foreach($template in $serverProfileTemplate.members)
                {
                    if($BasetemplateName -eq $template.name)
                    {
                        $baseTemplate = $template
                    }
                }
                Write-Host "Creating Server Profile Templates..." -ForegroundColor Yellow
                for($i = 0; $i -lt $TargetIpAddresses.Count; $i++)
                {
                    $targetIp = $TargetIpAddresses[$i]
                    for($j = 0; $j -lt $ProfileTemplateInputs.Count; $j++)
                    {   
                    
                        if($targetIp -ne $Global:ipAddress)
                        {   
                            Disconnect-HPOVMgmt           
                            $return = connectFusion -ipAddress $targetIp  -appUname $Global:UserName  -appPwd $Global:Password -authProvider $Global:authProvider
                            validateConnection                                   
                            $templateName = $ProfileTemplateInputs[$j]
                            #Create POST request JSON body
                            $new_spt_json = $baseTemplate | Select-Object -Property * -ExcludeProperty name,serverProfileDescription,category,created,modified,status,state,eTag,uri             
                            $new_spt_json | add-member -NotePropertyName name -NotePropertyValue $templateName
                            $response = Send-HPOVRequest -uri $Global:serverProfileTemplateUri POST $new_spt_json 
                            $task = $response.uri
                            $taskStatus = Wait-HPOVTaskComplete $task -timeout (New-TimeSpan -Minutes 10)
                            if($taskStatus.taskErrors -ne "null")
                            {                                
                                writeLog $taskStatus.taskErrors.message -debuglevel "ERROR"                                
                                $name+","+$targetIp+","+ $taskStatus.taskErrors.errorCode | Add-Content $Global:Create_ServerProfileTemplateError -Force
                                Write-Host " Failed: $name in $targetIp " -ForegroundColor Red 
                            }
                            elseif($taskStatus.taskState -eq "Completed" -or $taskStatus.taskState -eq "Running")
                            {
                                writeLog -message " $templateName is added to $targetIp"
                                Write-Host  "$templateName Added to $targetIp" -ForegroundColor Yellow
                                $templateName + ","+ $targetIp+","+ "Added!"| Add-Content $Global:Create_ServerProfileTemplateSuccess -Force 
                            }                        
                        }
                        else                           
                        {                   
                            $templateName = $ProfileTemplateInputs[$j]
                            #Create POST request JSON body
                            $new_spt_json = $baseTemplate | Select-Object -Property * -ExcludeProperty name,serverProfileDescription,category,created,modified,status,state,eTag,uri             
                            $new_spt_json | add-member -NotePropertyName name -NotePropertyValue $templateName
                         
                            $response = Send-HPOVRequest -uri $Global:serverProfileTemplateUri POST $new_spt_json  
                            $task = $response.uri
                            $taskStatus = Wait-HPOVTaskComplete $task -timeout (New-TimeSpan -Minutes 10)
                            if($taskStatus.taskErrors -ne "null")
                            {                                
                                writeLog $taskStatus.taskErrors.message -debuglevel "ERROR"                                
                                $templateName+","+$targetIp+","+ $taskStatus.taskErrors.errorCode | Add-Content $Global:Create_ServerProfileTemplateError -Force
                                Write-Host " Failed: $templateName in $targetIp " -ForegroundColor Red 
                            }
                            elseif($taskStatus.taskState -eq "Completed" -or $taskStatus.taskState -eq "Running")
                            {
                                $resourceName = $taskStatus.associatedResource.resourceName
                                writeLog -message " $templateName is added to $targetIp"
                                Write-Host  "$templateName Added to $targetIp" -ForegroundColor Yellow
                                $templateName+ ","+$targetIp+","+ "Added!"| Add-Content $Global:Create_ServerProfileTemplateSuccess -Force 
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "Entered basetemplate name $BasetemplateName is not present"
                $BasetemplateName +","+"-"+","+"not present" |Add-Content $Global:Create_ServerProfileTemplateError -Force
            }
        }
        catch
        {
            $ErrorMessage = $_.Exception.Message
            Write-Host $ErrorMessage -ForegroundColor Red
            writeLog -message $ErrorMessage -debuglevel "ERROR"
            exit 

        }
        
        Write-Host "View the report in " $Global:Create_ServerProfileTemplateSuccess
        Write-Host "view the error report in " $Global:Create_ServerProfileTemplateError -ForegroundColor Red
        writeLog "View the report in  $Global:Create_ServerProfileTemplateSuccess"
        writeLog "view the error report in $Global:Create_ServerProfileTemplateError"
      
        writeLog "FUNCTION END : CREATE-SERVER_PROFILE_TEMPLATE"
    }
}


function Add_Enclosures
{

    <#
        Function to add enclosures

    #>

    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the password")]
        [ValidateNotNullOrEmpty()]
        [System.String]$enclosureInputs, 
        
        [parameter(HelpMessage = "Enter the config state either Managed or Monitored  file ")]
        [string]$ConfigurationState = "Managed" 
    )
       
    Process
    {
        writeLog "FUNCTION BEGIN : ADD ENCLOSURES"
        CreateNewFile $Global:AddEnclosuresStatus $Global:AddEnclosuresErrorStatus
        
        if ($configurationState -ne "Managed" -and $configurationState -ne "Monitored") 
        {
            Write-Host "ERROR: Configuration state : $configurationState  is invalid please enter either 'Managed' or 'Monitored'" -ForegroundColor DarkRed
            writeLog "ERROR: Configuration state is invalid please enter either 'Managed' or 'Monitored'"
            return
        }
        $state = "Added"
        $hashtable = @{}
        
        $header = "Enclosure_name,Status"
        $header | Add-Content $Global:AddEnclosuresStatus
        $header | Add-Content $Global:AddEnclosuresErrorStatus    

        if ( $enclosureInputs )
        {
            Write-Host "Adding Enclosures... " -ForegroundColor Yellow
            writeLog  "Adding Enclosures... "
            
            $inputData = Import-csv $enclosureInputs
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                $csv_hostname = $input.hostname
                $csv_enclosuregroup = $input.enclosuregroup
                $csv_licensingIntent = $input.licensingIntent
                $csv_username = $input.username
                
                if ( $csv_hostname -eq $null -or $csv_enclosuregroup -eq $null -or $csv_licensingIntent -eq $null  -or $csv_username -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                } 
                                                  
                $enclGroup = Get-HPOVEnclosureGroup $csv_enclosuregroup
                
                $import = [PSCustomObject]@{
                            hostname             = $csv_hostname;
                            username             = $csv_username;
                            password             = $null;
                            licensingIntent      = $csv_licensingIntent;
                            enclosureGroupUri    = $enclGroup.uri;
                            firmwareBaselineUri  = $null;
                            forceInstallFirmware = $false;
                            updateFirmwareOn     = "EnclosureOnly" 
                }                    
                
                if ($EnclPassword -eq $null -or $EnclPassword -eq "")
                {
                    [System.Security.SecureString] $EnclPassword = Read-Host "Enter the one time password for enclosures to be added:" -AsSecureString
                    $decryptEnclPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($EnclPassword))
                }
                $import.password = $decryptEnclPassword 
 
                if($ConfigurationState -eq "Managed")
                {
                    <# $baseLine = Read-Host "enter the firmware version"
                    $fwuri = "/rest/firmware-drivers" + "?filter=version='$baseLine'"
                    $fwBaseLine = Send-HPOVRequest -uri $fwuri
                    $import.firmwareBaselineUri = $fwBaseLine.uri
		    $import.forceInstallFirmware = $true #>
                    $response = Send-HPOVRequest -uri "/rest/enclosures" POST $import
                    $response_uri = $response.uri
                    $resource_name = $csv_hostname  
                    if( $response_uri -ne $null)
                    {   
                        $hashtable.Add($response_uri,$resource_name)
                    }
                }
                elseif($ConfigurationState -eq "Monitored")
                {          
                    $response = Send-HPOVRequest -uri "/rest/enclosures" POST $import
                    $response_uri = $response.uri
                    $resource_name = $csv_hostname  
                    
                    if( $response_uri -ne $null)
                    {   
                        $hashtable.Add($response_uri,$resource_name)
                    }
                }
            }
            taskCompletionCheck $hashtable $Global:AddEnclosuresErrorStatus $Global:AddEnclosuresStatus $state
        }           
        writeLog "FUNCTION END : ADD ENCLOSURES"
    }
}



function Remove_enclosures
{
    <#
        Function to remove enclosures
    #>

    Param
    (           
        [parameter(Mandatory = $true, HelpMessage = "Enter the inventory file")]
        [ValidateNotNullOrEmpty()]
        [System.String]$enclosureInputs
    )

    Process
    {
        writeLog "FUNCTION BEGIN : REMOVE ENCLOSURES"
        $returnCode = connectFusion $ApplianceIP $UserName $Password "LOCAL"  
        validateConnection $returnCode
        CreateNewFile $Global:RemoveEnclosuresSuccess $Global:RemoveEnclosuresError
                   
        $state = "Removed!"
        $hashtable = @{}
      
        $header = "Enclosure_name,Status"
        $header | Add-Content $Global:RemoveEnclosuresSuccess
        $header | Add-Content $Global:RemoveEnclosuresError    

        if ( $enclosureInputs )
        {
            Write-Host "Removing Enclosures... " -ForegroundColor Yellow
            writeLog "Removing Enclosures... "
            $inputData = Import-csv $enclosureInputs
            $encljson = Send-HPOVRequest -uri "/rest/enclosures"
            
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                $csv_Enclosure_Name = $input.Enclosure_Name
                if ( $csv_Enclosure_Name -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }               
                if($encljson.members.name -contains $csv_Enclosure_Name)
                {
                    $encl = "/rest/enclosures" + "?filter=name='$csv_Enclosure_Name'"
                    $enclosure = Send-HPOVRequest -uri $encl
                    $enclUri = $enclosure.members.uri
                    $response = Send-HPOVRequest -uri $enclUri DELETE
                    $responseUri = $response.uri
                    $resourceName = $csv_Enclosure_Name
                    
                    if ($responseUri -ne $null)
                    {
                        $hashtable.Add( $responseUri,$resourceName)
                    }
                }
                elseif($encljson.members.name -notcontains $csv_Enclosure_Name)
                {
                    Write-Host "doesnot contain the given enclosure"
                }
            }
            taskCompletionCheck $hashtable $Global:RemoveEnclosuresError $Global:RemoveEnclosuresSuccess $state
            writeLog "FUNCTION END : REMOVE ENCLOSURES"
        }
    }
}


function Add_EnclosureGroup
{
    <#
        Function to add enclosure group    
    #>

    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the inventory file")]
        [ValidateNotNullOrEmpty()]
        [System.String]$enclosureGroupInputs
    )

    Process
    {
    
        writeLog "FUNCTION BEGIN : ADD ENCLOSURE GROUP"
        CreateNewFile $Global:AddEnclosureGroupSuccess $Global:AddEnclosureGroupError
                 
        $state = "Added!"
        $hashtable = @{}
      
        $header = "EnclosureGroupName,Status"
        $header | Add-Content $Global:AddEnclosureGroupSuccess
        $header | Add-Content $Global:AddEnclosureGroupError    

        if ( $enclosureGroupInputs )
        {
            Write-Host "Adding Enclosure Groups... " -ForegroundColor Yellow
            writeLog "Adding Enclosure Groups... "
            $inputData = Import-csv $enclosureGroupInputs
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                $csvEnclosureGroupName = $input.Enclosure_Group_Name
                $csvLIGName = $input.LIG_Name
                if ($csvEnclosureGroupName -eq $null -or $csvLIGName -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }

                $LIG = Send-HPOVRequest -uri "/rest/logical-interconnect-groups"
                if($LIG.members.name -contains $csvLIGName)
                {
                    $LigNameUri = "/rest/logical-interconnect-groups" + "?filter=name='$csvLIGName'"
                    $Lig = Send-HPOVRequest -uri $LigNameUri 
                    $LigUri = $Lig.members.uri
                    try
                    {
                        $response = New-HPOVEnclosureGroup $csvEnclosureGroupName $LigUri
                        $csvEnclosureGroupName+","+$state | Add-Content $Global:RemoveEnclosuresSuccess -Force
                        Write-Host "$csvEnclosureGroupName :$state"
                        writeLog -message "$csvEnclosureGroupName : $state"
                    }
                    catch
                    {
                        $ErrorMessage = $_.Exception.Message
                        Write-Host $ErrorMessage -ForegroundColor Red
                        writeLog -message $ErrorMessage -debuglevel "ERROR"
                       $csvEnclosureGroupName+","+$ErrorMessage | Add-Content $Global:RemoveEnclosuresError -Force  
                    }
                }
                elseif($LIG -notcontains $csvLIGName)
                {
                    Write-Host "LIG doesnot contains $csvLIGName group name"
                    writeLog -message "LIG doesnot contains $csvLIGName group name" -debuglevel "ERROR"
                    $csvEnclosureGroupName+","+ "LIG doesnot contains $csvLIGName group name" | Add-Content $Global:RemoveEnclosuresError -Force 
                }
            }
       }
       writeLog "FUNCTION END : ADD ENCLOSURE GROUP"       
    }
}

function Remove_EnclosureGroups
{
    <#
        Function to remove enclosure groups
    #>

    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the inventory file")]
        [ValidateNotNullOrEmpty()]
        [System.String]$enclosureGroupInputs
    )

    Process
    {
        writeLog "FUNCTION BEGIN : REMOVE ENCLOSURE GROUP"
        
        CreateNewFile $Global:RemoveEnclosureGroupSuccess $Global:RemoveEnclosureGroupError
        $state = "Removed!"
        $hashtable = @{}
              
        $header = "EnclosureGroupName,Status"
        $header | Add-Content $Global:RemoveEnclosureGroupSuccess
        $header | Add-Content $Global:RemoveEnclosureGroupError    

        if ( $enclosureGroupInputs )
        {
            Write-Host "Adding Enclosure Groups... " -ForegroundColor Yellow
            writeLog "Adding Enclosure Groups... "
            $inputData = Import-csv $enclosureGroupInputs
          
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                $csvEnclosureGroupName = $input.Enclosure_Group_Name
                if ($csvEnclosureGroupName -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                try
                {
                    $response = Remove-HPOVEnclosureGroup $csvEnclosureGroupName
                    $csvEnclosureGroupName+","+$state | Add-Content $Global:RemoveEnclosureGroupSuccess -Force
                    Write-Host "$csvEnclosureGroupName :$state"
                    writeLog -message "$csvEnclosureGroupName : $state"
                }
                catch
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Host $ErrorMessage -ForegroundColor Red
                    writeLog -message $ErrorMessage -debuglevel "ERROR"
                    $csvEnclosureGroupName+","+$ErrorMessage | Add-Content $Global:RemoveEnclosureGroupError -Force
                }
            }
        }
        writeLog "FUNCTION END : REMOVE ENCLOSURE GROUP"
    }
}


function Add_LogicalInterconnectGroups
{
    <#
        Function to add LIGs
    #>
    Param
    (
        [parameter(Mandatory = $true, HelpMessage = "Enter the inventory file")]
        [ValidateNotNullOrEmpty()]
        [System.String]$Name,

        [parameter(Mandatory = $true, HelpMessage = "Enter the inventory file")]
        [ValidateNotNullOrEmpty()]
        [System.String]$LogicalInterconnectGroups
        
    )

    Process
    {
        writeLog "FUNCTION BEGIN :ADD LOGICAL INTERCONNECT GROUPS"
        
        CreateNewFile $Global:AddLogicalInterconnectGroupsSuccess $Global:AddLogicalInterconnectGroupsError
                   
        $state = "Added!"
        $hashtable = @{}
              
        $header = "EnclosureGroupName,Status"
        $header | Add-Content $Global:AddLogicalInterconnectGroupsSuccess
        $header | Add-Content $Global:AddLogicalInterconnectGroupsError    

        if ( $LogicalInterconnectGroups )
        {
            Write-Host "Adding LIGs... " -ForegroundColor Yellow
            writeLog "Adding LIGs... "
            $inputData = Import-csv $LogicalInterconnectGroups
            
            $path = "$Global:root\Input_JSON\Add_LIG.json"
            $Json = Get-Content -Path $path -Raw | ConvertFrom-Json 
            $Json.name = $Name
          
            $count  = 0
            foreach($bay in $inputData)
            {             
                $bayNumber = $bay.Bay_Number
                $interConnectTypeName = $bay.InterConnect_Types
                $interConnectType = "/rest/interconnect-types"+"?filter=name='$interConnectTypeName'"
                $interConnectResponse = Send-HPOVRequest -uri $interConnectType
                $interConnectTypeUri = $interConnectResponse.members.uri             
                $inputBayNumber = $Json.interconnectMapTemplate.interconnectMapEntryTemplates.logicalLocation.locationEntries          
                $interconnecttemplates = $Json.interconnectMapTemplate.interconnectMapEntryTemplates[$count]
                
                for($j = 0 ; $j -le 16 ; $j++)
                {
                    if(($bayNumber -eq $inputBayNumber[$j].relativeValue)-and ($inputBayNumber[$j].type -eq "Bay"))
                    {
                        $interconnecttemplates.permittedInterconnectTypeUri = $interConnectTypeUri
                    }
                }
                $count++
            }
            $response = Send-HPOVRequest -uri "/rest/logical-interconnect-groups" POST $Json
            $responseUri= $response.uri
            $resourceName = $Name
            if ($responseUri -ne $null)
            {
                $hashtable.Add( $responseUri,$resourceName)
            }
            taskCompletionCheck $hashtable $Global:AddNetworksErrorStatus $Global:AddNetworksSuccessStatus  $state 
        }
    }
}


function AddNetworks
{
    <#
        Function to add networks
    #>
    Param
    (     
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$Network_List     
    )

    Process 
    {
        writeLog -message "FUNCTION BEGIN : ADD NETWORKS"

        CreateNewFile $Global:AddNetworksSuccessStatus $Global:AddNetworksErrorStatus
        $hashtable = @{}
        $state = "Added!"
        $header = "Network_Name,Type,Status"
        $header | Add-Content $Global:AddNetworksSuccessStatus
        $header | Add-Content $Global:AddNetworksErrorStatus

        if ( $Network_List )
        {
            Write-Host "Adding networks... " -ForegroundColor Yellow
            writeLog "Adding networks... "

            $inputData = Import-csv $Network_List
            foreach ($input in $inputData )
            {
                $csv_networkName = $input.Network_Name
                $csv_type = $input.type
                $csv_vlanId = $input.vlanId
                $csv_smartlink = $input.SmartLink
                $csv_privateNetwork = $input.privateNetwork
                $csv_ethernetNetworkType = $input.ethernetNetworkType
                $csv_purpose = $input.purpose
                $csv_linkStabilityTime = $input.linkStabilityTime
                $csv_autoLoginRedistribution = $input.autoLoginRedistribution
                $csv_fabricType = $input.fabricType
 
                if ( $csv_networkName -eq $null -or $csv_type -eq $null -or $csv_vlanId -eq $null -or $csv_smartlink -eq $null -or $csv_privateNetwork -eq $null -or $csv_purpose -eq $null -or $csv_ethernetNetworkType -eq $null -or $csv_linkStabilityTime -eq $null -or $csv_autoLoginRedistribution -eq $null -or $csv_fabricType -eq $null )
                {
                   Write-Host " Please verify the Inventory File "
                   writeLog " Please verify the Inventory File "
                   exit
                }

                $ethernetNW = Send-HPOVRequest -uri $Global:ethernetNetworksuri -method GET
                $FCNW = Send-HPOVRequest -uri $Global:FCNetworksuri -method GET
                $FCoENW = Send-HPOVRequest -uri $Global:FCoENetworksuri -method GET

                if($csv_type -eq "Ethernet")
                {
                    if(!($ethernetNW.members.name -contains $csv_networkName))
                    {
                        $vlanlow = "1"
                        $vlanhigh = "4094"
                        if(($csv_vlanId -ge $vlanlow) -and ($csv_vlanId -le $vlanhigh))
                        {                    
                            
                            if($version -eq "200")
                            {
                                $new_csv_type = "ethernet-networkV3"
                            }
                            elseif($version -eq "300")
                            {
                                $new_csv_type = "ethernet-networkV300"
                            }
                            $path = Get-Content $Global:addNetworksJson -Raw | convertFrom-json
                            $path | add-member -NotePropertyName vlanId  -NotePropertyValue $csv_vlanId
                            $path | add-member -NotePropertyName purpose -NotePropertyValue $csv_purpose
                            $path | add-member -NotePropertyName name -NotePropertyValue $csv_networkName
                            $csv_smartlink = $csv_smartlink.ToLower()
                            $csv_privateNetwork = $csv_privateNetwork.ToLower()
                            $path | add-member -NotePropertyName smartLink -NotePropertyValue $csv_smartlink
                            $path | add-member -NotePropertyName privateNetwork -NotePropertyValue $csv_privateNetwork
                            $path | add-member -NotePropertyName connectionTemplateUri -NotePropertyValue $null
                            $path | add-member -NotePropertyName ethernetNetworkType -NotePropertyValue $csv_ethernetNetworkType
                            $path | add-member -NotePropertyName type -NotePropertyValue $new_csv_type

                            $response = Send-HPOVRequest -uri $Global:ethernetNetworksuri POST $path
                            $responseUri = $response.uri
                            $resourceName = $csv_networkName
                        
                            if ($responseUri -ne $null)
                            {
                                $hashtable.Add( $responseUri,$resourceName)
                            } 
                        }
                        else
                        {
                            Write-Host "Enter VLAN values between 1 and 4094 for $csv_networkName" -ForegroundColor Red
                        }
                    }
                    elseif($ethernetNW.members.name -contains $csv_networkName)
                    {
                        Write-Host "The entered Ethernet Network name is already present" -ForegroundColor Red
                    }
                }
                
                elseif($csv_type -eq "FC")
                {
                    if(!($FCNW.members.name -contains $csv_networkName))
                    {               
                        
                       if($version -eq "200")
                       {
                            $new_csv_type = "fc-networkV2"
                       }
                       elseif($version -eq "300")
                       {
                            $new_csv_type = "fc-networkV300"
                       }
                        $path = Get-Content $Global:addNetworksJson -Raw | convertFrom-json
                        $path | add-member -NotePropertyName name -NotePropertyValue $csv_networkName
                        $path | add-member -NotePropertyName connectionTemplateUri -NotePropertyValue $null
                        $path | add-member -NotePropertyName linkStabilityTime -NotePropertyValue $csv_linkStabilityTime
                        $csv_autoLoginRedistribution= $csv_autoLoginRedistribution.ToLower()
                        $path | add-member -NotePropertyName autoLoginRedistribution -NotePropertyValue $csv_autoLoginRedistribution
                        $path | add-member -NotePropertyName fabricType -NotePropertyValue $csv_fabricType
                        $path | add-member -NotePropertyName type -NotePropertyValue $new_csv_type

                        $response = Send-HPOVRequest -uri $Global:FCNetworksuri POST $path
                        $responseUri = $response.uri
                        $resourceName = $csv_networkName
                        
                        if ($responseUri -ne $null)
                        {
                            $hashtable.Add( $responseUri,$resourceName)
                        } 
                    }
                    elseif($FCNW.members.name -contains $csv_networkName)
                    {
                       Write-Host "The entered FC Network name is already present" -ForegroundColor Red
                    }
                }
                
                elseif($csv_type -eq "FCoE")
                {
                    if(!($FCoENW.members.name -contains $csv_networkName))
                    {  
                        $vlanlow = "2"
                        $vlanhigh = "4094"
                        if(($csv_vlanId -ge $vlanlow) -and ($csv_vlanId -le $vlanhigh))
                        {  
                            if($version -eq "200")
                            {
                                $new_csv_type = "fcoe-network"
                            }
                            elseif($version -eq "300")
                            {
                                $new_csv_type = "fcoe-networkV300"
                            }                            
                            $path = Get-Content $Global:addNetworksJson -Raw | convertFrom-json
                            $path | add-member -NotePropertyName name -NotePropertyValue $csv_networkName
                            $path | add-member -NotePropertyName vlanId  -NotePropertyValue $csv_vlanId
                            $path | add-member -NotePropertyName connectionTemplateUri -NotePropertyValue $null
                            $path | add-member -NotePropertyName type -NotePropertyValue $new_csv_type
                        
                            $response = Send-HPOVRequest -uri $Global:FCoENetworksuri POST $path
                            $responseUri = $response.uri
                            $resourceName = $csv_networkName
                        
                            if ($responseUri -ne $null)
                            {
                                $hashtable.Add( $responseUri,$resourceName)
                            } 
                        }
                        else
                        {
                        Write-Host "Enter VLAN values between 2 and 4094 for $csv_networkName" -ForegroundColor Red
                        }
                    }

                    elseif($FCoENW.members.name -contains $csv_networkName)
                    {
                        Write-Host "The entered FCoE Network name is already present" -ForegroundColor Red
                    }
                }
            }
            taskCompletionCheck $hashtable $Global:AddNetworksErrorStatus $Global:AddNetworksSuccessStatus  $state
            Write-Host "View the error report in $Global:AddNetworksErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:AddNetworksSuccessStatus" 
        }
        writeLog -message "FUNCTION BEGIN : ADD NETWORKS"
    }
}


function Remove-Networks
{
    <#
        Function to Remove networks
    #>
    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$Network_List     
    )

    Process 
    {
        writeLog -message "FUNCTION BEGIN : REMOVE NETWORKS"

        CreateNewFile $Global:RemoveNetworksSuccessStatus $Global:RemoveNetworksErrorStatus
        $hashtable = @{}
        $State = "Removed!"
        $header = "Network_Name,Type,Status"
        $header | Add-Content $Global:RemoveNetworksErrorStatus
        $header | Add-Content $Global:RemoveNetworksSuccessStatus

        $ethernetNW = Send-HPOVRequest -uri $Global:ethernetNetworksuri GET
        $FCNW = Send-HPOVRequest -uri $Global:FCNetworksuri -method GET
        $FCoENW = Send-HPOVRequest -uri $Global:FCoENetworksuri -method GET

       if ($Network_List)
       {
           Write-Host "Deleting in Progress ... " -ForegroundColor Yellow
           writeLog "Deleting in Progress ... "
           
           $inputData = Import-csv $Network_List
           foreach ($input in $inputData )
           {
               $csv_nw = $input.Network_name
               $csv_type = $input.Type
                    
               if ( $csv_nw -eq $null -or $csv_type -eq $null)
               {
                   Write-Host " Please verify the Inventory File "
                   writeLog " Please verify the Inventory File "
                   exit
               }

               if($csv_type -eq "Ethernet")
               {
                   if($ethernetNW.members.name -contains $csv_nw)
                   {
                       foreach($nw in $ethernetNW.members.GetEnumerator())
                       {
                           if($nw.name -eq $csv_nw)
                           {
                               $response = Remove-HPOVResource -nameOruri $nw.uri -force
                               $responseUri = $response.uri
                               $resourceName = $csv_nw
                        
                               if ($responseUri -ne $null)
                               {
                                   $hashtable.Add( $responseUri,$resourceName)
                               } 
                           }
                        }
                    }
                    else
                    {
                        Write-Host " $csv_nw does not exists" -ForegroundColor Red
                        writeLog " $csv_nw does not exists"
                        $csv_nw + "," + "Does not exists" | Add-Content $Global:RemoveNetworksErrorStatus -Force 
                    }
                }

                elseif($csv_type -eq "FC")
                {
                    if($FCNW.members.name -contains $csv_nw)
                    {
                        foreach($nw in $FCNW.members.GetEnumerator())
                        {
                            if($nw.name -eq $csv_nw)
                            {
                                $response = Remove-HPOVResource -nameOruri $nw.uri -force
                                $responseUri = $response.uri
                                $resourceName = $csv_nw
                        
                                if ($responseUri -ne $null)
                                {
                                    $hashtable.Add( $responseUri,$resourceName)
                                } 
                            }
                        }
                    }
                    else
                    {
                        Write-Host " $csv_nw does not exists" -ForegroundColor Red
                        writeLog " $csv_nw does not exists"
                        $csv_nw + "," + "Does not exists" | Add-Content $Global:RemoveNetworksErrorStatus -Force 
                    }
                }
                
                elseif($csv_type -eq "FCoE")
                {
                    if($FCoENW.members.name -contains $csv_nw)
                    {
                        foreach($nw in $FCoENW.members.GetEnumerator())
                        {
                            if($nw.name -eq $csv_nw)
                            {
                                $response = Remove-HPOVResource -nameOruri $nw.uri -force
                                $responseUri = $response.uri
                                $resourceName = $csv_nw
                        
                                if ($responseUri -ne $null)
                                {
                                    $hashtable.Add( $responseUri,$resourceName)
                                } 
                            }
                        }
                    }
                    else
                    {
                        Write-Host " $csv_nw does not exists" -ForegroundColor Red
                        writeLog " $csv_nw does not exists"
                        $csv_nw + "," + "Does not exists" | Add-Content $Global:RemoveNetworksErrorStatus -Force 
                    }
                }
            }
            taskCompletionCheck $hashtable $Global:RemoveNetworksErrorStatus $Global:RemoveNetworksSuccessStatus $state
            Write-Host "View the error report in $Global:RemoveNetworksErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:RemoveNetworksSuccessStatus" 
        }
        writeLog -message "FUNCTION END : REMOVE NETWORKS"
    }
}


function Create_NetworkSet
{
    <#
        Function to create a network set
    #>
    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the JSON file")]
        [ValidateNotNullOrEmpty()]
        [System.string]$Networks_List     
    )

    Process 
    {
        writeLog -message "FUNCTION BEGIN : CREATE NETWORK SET"

        CreateNewFile $Global:AddNetworkSetSuccessStatus $Global:AddNetworkSetErrorStatus
        $state = "Added!"
        $hashtable = @{}  
        $header = "Network_Name,Type,Status"
        $header | Add-Content $Global:AddNetworkSetErrorStatus
        $header | Add-Content $Global:AddNetworkSetSuccessStatus

        $NetworkSets = Send-HPOVRequest -uri $Global:Networkset GET
        $ethernetNW = Send-HPOVRequest -uri $Global:ethernetNetworksuri GET
        $FCNW = Send-HPOVRequest -uri $Global:FCNetworksuri -method GET
        $FCoENW = Send-HPOVRequest -uri $Global:FCoENetworksuri -method GET

        if ($Networks_List)
        {
            Write-Host "Adding NetworkSet in Progress ... " -ForegroundColor Yellow
            writeLog "Adding NetworkSet in Progress ... "
            
            $networkSetsParams = Get-Content $Networks_List -Raw | ConvertFrom-Json

            foreach($setName in $networkSetsParams.NetworkSets.GetEnumerator())
            {
                $set_Name = $setName.name
                if($NetworkSets.members.name -notcontains $setName.name)
                {
                    foreach($nets in $setName.networks.GetEnumerator())
                    {
                        foreach($eth in $ethernetNW.members.GetEnumerator())
                        {
                            if($nets -eq $eth.name)
                            {
                                $ethUri = $eth.uri        
                                [System.Array]$networkUris  += $ethUri
                            }
                        } 
                    }
                    if ($networkUris.Count -ge 1)
                    {
                        $newSet = [PSCustomObject]@{
                            name        = $setName.name;
                            networkUris = $networkUris;
                            type    = $networkSetsParams.type;
                            }      
                            $response = Send-HPOVRequest -uri $Global:Networkset POST $newSet
                            $responseUri = $response.uri
                            $resourceName = $networkSetsParams.NetworkSets.name
                        
                           if ($responseUri -ne $null)
                           {
                               $hashtable.Add( $responseUri,$resourceName)
                           }
                    }
                }
                else
                {
                    Write-Host "NetworkSet name" $set_Name "is already present" -ForegroundColor Red
                    writeLog "NetworkSet name $set_Name is already present"
                }
            }
            taskCompletionCheck $hashtable $Global:AddNetworkSetErrorStatus $Global:AddNetworkSetSuccessStatus $state
            Write-Host "View the error report in $Global:AddNetworkSetErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:AddNetworkSetSuccessStatus" 
        }
        writeLog -message "FUNCTION END : CREATE NETWORK SET"
    }
}

function Remove-NetworkSet
{
    <#
        Function to Remove network set
    #>

    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$NetworkSet_List     
    )

    Process 
    {
        writeLog -message "FUNCTION BEGIN : REMOVE NETWORKSET"

        CreateNewFile $Global:RemoveNetworkSetSuccessStatus $Global:RemoveNetworkSetErrorStatus
        $hashtable = @{}
        $State = "Removed!"
        $header = "Network_Name,Type,Status"
        $header | Add-Content $Global:RemoveNetworkSetErrorStatus
        $header | Add-Content $Global:RemoveNetworkSetSuccessStatus
        
        $NetworkSets = Send-HPOVRequest -uri $Global:Networkset GET

        if ($NetworkSet_List)
        {
           Write-Host "Deleting in Progress ... " -ForegroundColor Yellow
           writeLog "Deleting in Progress ... "
           
           $inputData = Import-csv $NetworkSet_List
           foreach ($input in $inputData )
           {
               $csv_nwSet = $input.NetworkSet_name
                    
               if ($csv_nwSet -eq $null)
               {
                   Write-Host " Please verify the Inventory File "
                   writeLog " Please verify the Inventory File "
                   exit
               }
               if($NetworkSets.members.name -contains $csv_nwSet)
               {
                   foreach($nwSet in $NetworkSets.members.GetEnumerator())
                   { 
                      if($nwSet.name -eq $csv_nwSet)
                       {
                           $response = Remove-HPOVResource -nameOruri $nwSet.uri -force
                           $responseUri = $response.uri
                           $resourceName = $csv_nwSet
                        
                           if ($responseUri -ne $null)
                           {
                               $hashtable.Add( $responseUri,$resourceName)
                           } 
                       }
                    }
                }
                else
                {
                    Write-Host "$csv_nwSet does not exists" -ForegroundColor Red
                    writeLog "$csv_nwSet does not exists"
                    $csv_nwSet + "," + "Does not exists" | Add-Content $Global:RemoveNetworkSetErrorStatus -Force 
                }
            }
            taskCompletionCheck $hashtable $Global:RemoveNetworkSetErrorStatus $Global:RemoveNetworkSetSuccessStatus $state
            Write-Host "View the error report in $Global:RemoveNetworkSetErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:RemoveNetworkSetSuccessStatus" 
        }
        writeLog -message "FUNCTION END : REMOVE NETWORKSET"
    }
}


function Add-StorageSystem
{
    <#
        Function to a Storage system
    #>
    Param 
    (
        [parameter(Mandatory = $true, HelpMessage = "Enter the host name (FQDN) or IP of the Storage System and the Domain name.")]
        [ValidateNotNullOrEmpty()]
        [string]$StorageSytemInput,
         
        [parameter(Mandatory = $true, HelpMessage = "Enter the administrative user name (i.e. 3paradm).")]
        [ValidateNotNullOrEmpty()]
        [string]$username="",

        [parameter(Mandatory = $false, HelpMessage = "Specify the Host Ports and Expected Network in an Array of PSCustomObject entries. Example: @{`"1:1:1`"=`"Fabric A`";`"2:2:2`"=`"Fabric B`"}")]
        [ValidateNotNullOrEmpty()]
        [PsCustomObject]$Ports
    )
    
    Process
    {
        if(!$StorageSystemPassword)
        {
            [System.Security.SecureString]$StorageSystemPassword = Read-Host "Enter the Storage system password" -AsSecureString
            $decryptStorageSystemPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($StorageSystemPassword))            
        }
        
        writeLog -message "FUNCTION BEGIN : ADD STORAGE SYSTEM"

        CreateNewFile $Global:AddStorageSystemSuccessStatus $Global:AddStorageSystemErrorStatus
        $hashtable = @{}
        $State = "Added!"
        $header = "StorageSystemName,Status"
        $header | Add-Content $Global:AddStorageSystemSuccessStatus
        $header | Add-Content $Global:AddStorageSystemErrorStatus 
    
        if ( $StorageSytemInput )
        {
            $inputData = Import-csv $StorageSytemInput
            foreach ($input in $inputData )
            {
                $csv_hostname = $input.Storage_hostname
                $csv_domain = $input.Domain
                if ($csv_hostname -eq $null -or $csv_domain -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                try
                {
                    $response = Add-HPOVStorageSystem -hostname $csv_hostname -username $username -password $decryptStorageSystemPassword -Domain $csv_domain
                    $csv_hostname+","+$state | Add-Content $Global:AddStorageSystemSuccessStatus -Force
                    Write-Host "$csv_hostname :$state"
                    writeLog -message "$csv_hostname : $state"
                }
                catch
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Host $ErrorMessage -ForegroundColor Red
                    writeLog -message $ErrorMessage -debuglevel "ERROR"
                    $csv_hostname+","+$ErrorMessage | Add-Content $Global:AddStorageSystemErrorStatus -Force  
                }
                Write-Host "View the error report in $Global:AddStorageSystemErrorStatus" -ForegroundColor Red
                Write-Host "View the success report in $Global:AddStorageSystemSuccessStatus" 
            }
            writeLog -message "FUNCTION END : ADD STORAGE SYSTEM"
        }    
    }
}

function Remove-StorageSystem
{
    <#
        Function to remove storage system
    #>
    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$StorageSystem_List     
    )

    Process 
    {
        writeLog -message "FUNCTION BEGIN : REMOVE STORAGE SYSTEM"

        CreateNewFile $Global:RemoveStorageSystemSuccessStatus $Global:RemoveStorageSystemErrorStatus
        $hashtable = @{}
        $State = "Removed!"
        $header = "Name,Status"
        $header | Add-Content $Global:RemoveStorageSystemSuccessStatus
        $header | Add-Content $Global:RemoveStorageSystemErrorStatus
        
        $StorageSystem = Send-HPOVRequest -uri $Global:storageSystemUri GET

        if ($StorageSystem_List)
        {
            Write-Host "Deleting in Progress ... " -ForegroundColor Yellow
            writeLog "Deleting in Progress ... "
           
            $inputData = Import-csv $StorageSystem_List
            foreach ($input in $inputData )
            {
                $csv_name = $input.StorageSystem_name
                    
                if ($csv_name -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                if($StorageSystem.members.name -contains $csv_name)
                {
                    try
                    {
                        $response = Remove-HPOVStorageSystem -storageSystem $csv_name -force
                        $responseUri = $response.uri
                        $resourceName = $csv_name
                        
                        if ($responseUri -ne $null)
                        {
                            $hashtable.Add( $responseUri,$resourceName)
                        } 
                    } 
                    catch
                    {
                        $ErrorMessage = $_.Exception.Message
                        Write-Host $ErrorMessage -ForegroundColor Red
                        writeLog -message $ErrorMessage -debuglevel "ERROR"
                        $csv_name+","+$ErrorMessage | Add-Content $Global:RemoveStorageSystemErrorStatus -Force  
                    }
                }
                else
                {
                    Write-Host "$csv_name does not exists" -ForegroundColor Red
                    writeLog "$csv_name does not exists"
                    $csv_name + "," + "Does not exists" | Add-Content $Global:RemoveStorageSystemErrorStatus -Force 
                }
            }
            taskCompletionCheck $hashtable $Global:RemoveStorageSystemErrorStatus $Global:RemoveStorageSystemSuccessStatus $state
            Write-Host "View the error report in $Global:RemoveStorageSystemErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:RemoveStorageSystemSuccessStatus" 
        }
        writeLog -message "FUNCTION END : REMOVE STORAGE SYSTEM"
    }
}

function Add-StoragePool
{
    <#
        Function to add storage pool
    #>

    Param 
    (
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$Storagepool_List 
    )
    
    process
    {
        writeLog -message "FUNCTION BEGIN : ADD STORAGE POOL"

        $state = "Added!"
        CreateNewFile $Global:AddStoragePoolSuccessStatus $Global:AddStoragePoolErrorStatus
        $hashtable = @{}
        $State = "Added!"
        $header = "StoragePoolName,Status"
        $header | Add-Content $Global:AddStoragePoolSuccessStatus
        $header | Add-Content $Global:AddStoragePoolErrorStatus 

        if ($Storagepool_List)
        {
            $inputData = Import-csv $Storagepool_List
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                $csv_storageSystem = $input.storageSystem
                $csv_pool = $input.poolName
                    
                if ($csv_storageSystem -eq $null -or $csv_pool -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
        
                try
                {
                    $task = Add-HPOVStoragePool -StorageSystem $csv_storageSystem -poolName $csv_pool
                    $csv_pool+","+$state | Add-Content $Global:AddStoragePoolSuccessStatus -Force
                    Write-Host "$csv_pool :$state"
                    writeLog -message "$csv_pool :$state" -debuglevel 
                   
                }
                catch
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Host $ErrorMessage -ForegroundColor Red
                    writeLog -message $ErrorMessage -debuglevel "ERROR"
                    $csv_pool+","+$ErrorMessage | Add-Content $Global:AddStoragePoolErrorStatus -Force  
                }
            }
            Write-Host "View the error report in $Global:AddStoragePoolErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:AddStoragePoolSuccessStatus"
        }
        writeLog -message "FUNCTION BEGIN : ADD STORAGE POOL"       
    }
}


function Remove-StoragePool
{
    <#
        Function to remove storage pool
    #>

    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$StoragePool_List     
    )

    Process 
    {
        writeLog -message "FUNCTION BEGIN : REMOVE STORAGE POOL"

        CreateNewFile $Global:RemoveStoragePoolSuccessStatus $Global:RemoveStoragePoolErrorStatus
        $hashtable = @{}
        $State = "Removed!"
        $header = "Name,Status"
        $header | Add-Content $Global:RemoveStoragePoolSuccessStatus
        $header | Add-Content $Global:RemoveStoragePoolErrorStatus
        
        $StoragePool = Send-HPOVRequest -uri $Global:storagePoolUri GET

        if ($StoragePool_List)
        {
            Write-Host "Deleting in Progress ... " -ForegroundColor Yellow
            writeLog "Deleting in Progress ... "
           
            $inputData = Import-csv $StoragePool_List
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                $csv_name = $input.StoragePool
                    
                if ($csv_name -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                if($StoragePool.members.name -contains $csv_name)
                {
                    try
                    {
                        $response = Remove-HPOVStoragePool -storagePool $csv_name 
                        $responseUri = $response.uri
                        $resourceName = $csv_name
                        
                        if ($responseUri -ne $null)
                        {
                            $hashtable.Add( $responseUri,$resourceName)
                        } 
                    } 
                    catch
                    {
                        $ErrorMessage = $_.Exception.Message
                        Write-Host $ErrorMessage -ForegroundColor Red
                        writeLog -message $ErrorMessage -debuglevel "ERROR"
                        $csv_name+","+$ErrorMessage | Add-Content $Global:RemoveStoragePoolErrorStatus -Force  
                    }
                }
                else
                {
                    Write-Host "$csv_name does not exists" -ForegroundColor Red
                    writeLog "$csv_name does not exists"
                    $csv_name + "," + "Does not exists" | Add-Content $Global:RemoveStoragePoolErrorStatus -Force 
                }
            }
            taskCompletionCheck $hashtable $Global:RemoveStoragePoolErrorStatus $Global:RemoveStoragePoolSuccessStatus $state
            Write-Host "View the error report in $Global:RemoveStoragePoolErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:RemoveStoragePoolSuccessStatus" 
        }
        writeLog -message "FUNCTION END : REMOVE STORAGE POOL"
    }
}

function Add-VolumeTemplate
{
    <#
        Function to add volume template
    #>
    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$volumeInputs     
    )

    Process 
    {
        writeLog -message "FUNCTION BEGIN : ADD VOLUME TEMPLATE"

        CreateNewFile $Global:AddVolumeTemplateSuccessStaus $Global:AddVolumeTemplateErrorStatus
        $hashtable = @{}
        $State = "Added!"
        $header = "VolumeTemplateName,Status"
        $header | Add-Content $Global:AddVolumeTemplateSuccessStaus
        $header | Add-Content $Global:AddVolumeTemplateErrorStatus
        
        if ($volumeInputs)
        {
          
           $inputData = Import-csv $volumeInputs
           foreach ($input in $inputData )
           {
               #to import all the attributes present in the input file. 
               $csv_name = $input.name
               $csv_storagePool = $input.storagePool
               $csv_capacity = $input.capacity
                        
               if ($csv_name -eq $null -or $csv_storagePool -eq $null -or $csv_capacity -eq $null )
               {
                   Write-Host " Please verify the Inventory File "
                   writeLog " Please verify the Inventory File "
                   exit
               }
               try
               {
                    $response = New-HPOVStorageVolumeTemplate -templateName $csv_name -storagePool $csv_storagePool -capacity $csv_capacity 
                    Write-Host "$csv_name :$state"
                    writeLog -message "$csv_name :$state" 
                    $csv_name+","+$state | Add-Content $Global:AddVolumeTemplateSuccessStaus -Force
               }
               catch
               {
                   $ErrorMessage = $_.Exception.Message
                   Write-Host $ErrorMessage -ForegroundColor Red
                   writeLog -message $ErrorMessage -debuglevel "ERROR"
                   $csv_name+","+$ErrorMessage | Add-Content $Global:AddVolumeTemplateErrorStatus -Force  
               }       
           }
           Write-Host "View the error report in $Global:AddVolumeTemplateErrorStatus" -ForegroundColor Red
           Write-Host "View the success report in $Global:AddVolumeTemplateSuccessStaus"
       }
       writeLog -message "FUNCTION END : ADD VOLUME TEMPLATE"
   }
}

#not returning response
function Remove-VolumeTemplate
{
    <#
        Function to remove volume template
    #>

    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$VolumeTemplate_List     
    )

    Process 
    {
        writeLog -message "FUNCTION BEGIN : REMOVE VOLUME TEMPLATE"

        CreateNewFile $Global:RemoveVolumeTemplateSuccessStatus $Global:RemoveVolumeTemplateErrorStatus
        $hashtable = @{}
        $State = "Removed!"
        $header = "Name,Status"
        $header | Add-Content $Global:RemoveVolumeTemplateSuccessStatus
        $header | Add-Content $Global:RemoveVolumeTemplateErrorStatus
        
        $VolumeTemplate = Send-HPOVRequest -uri $Global:volumeTemplateUri GET

        if ($VolumeTemplate_List)
        {
            Write-Host "Deleting in Progress ... " -ForegroundColor Yellow
            writeLog "Deleting in Progress ... "
           
            $inputData = Import-csv $VolumeTemplate_List
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                $csv_name = $input.VolumeTemplate
                    
                if ($csv_name -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                if($VolumeTemplate.members.name -contains $csv_name)
                {
                    try
                    {
                        #no response returned. check it
                        $response = Send-HPOVRequest -uri $VolumeTemplate.members.uri DELETE
                        $responseUri = $response.uri
                        $resourceName = $csv_name
                        
                        if ($responseUri -ne $null)
                        {
                            $hashtable.Add( $responseUri,$resourceName)
                        } 
                    } 
                    catch
                    {
                        $ErrorMessage = $_.Exception.Message
                        Write-Host $ErrorMessage -ForegroundColor Red
                        writeLog -message $ErrorMessage -debuglevel "ERROR"
                        $csv_name+","+$ErrorMessage | Add-Content $Global:RemoveVolumeTemplateErrorStatus -Force  
                    }
                }
                else
                {
                    Write-Host "$csv_name does not exists" -ForegroundColor Red
                    writeLog "$csv_name does not exists"
                    $csv_name + "," + "Does not exists" | Add-Content $Global:RemoveVolumeTemplateErrorStatus -Force 
                }
            }
            taskCompletionCheck $hashtable $Global:RemoveVolumeTemplateErrorStatus $Global:RemoveVolumeTemplateSuccessStatus $state
            Write-Host "View the error report in $Global:RemoveVolumeTemplateErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:RemoveVolumeTemplateSuccessStatus" 
        }
        writeLog -message "FUNCTION END : REMOVE VOLUME TEMPLATE"
    }
}

function Add-StorageVolume
{
    <#
        Function to add storage volume
    #>
    Param 
    (
        [parameter (Mandatory = $true, HelpMessage = "Enter the input file (i.e input_to_AddStorageVolume.csv).")]
        [ValidateNotNullOrEmpty()]
        [string]$volumeDetails
    )

    process
    {
        writeLog -message "FUNCTION BEGIN : ADD STORAGE VOLUME"

        $storagePools_json = Send-HPOVRequest -uri $Global:storagePoolUri GET 
        $storageSystem_json = Send-HPOVRequest -uri $Global:storageSystemUri GET 
        $volumeTemplate_json = Send-HPOVRequest -uri $Global:volumeTemplateUri GET
        
        CreateNewFile $Global:AddVolumeSuccessStatus $Global:AddVolumeErrorStatus
        $hashtable = @{}
        $State = "Added!"
        $header = "Name,Status"
        $header | Add-Content $Global:AddVolumeSuccessStatus
        $header | Add-Content $Global:AddVolumeErrorStatus
        
        if ( $volumeDetails )
        {
            $selection  = Read-Host "Do you want to create StorageVolume from a volume template? (y/n)"
            if($selection -eq "n" -or $selection -eq "N")
            {
                $inputData = Import-csv $volumeDetails
                foreach ($input in $inputData )
                {
                    #to import all the attributes present in the input file. 
                    $csvvolumeName = $input.volumeName
                    $csvStoragePool = $input.StoragePool
                    $csvStorageSystem = $input.StorageSystem
                    $csvVolumeTemplate = $input.VolumeTemplate
                    $csvcapacity = $input.capacity

                    if ( $csvvolumeName -eq $null -or  $csvStoragePool -eq $null -or $csvStorageSystem -eq $null -or $csvcapacity -eq $null)
                    {
                        Write-Host " Please verify the Inventory File "
                        writeLog " Please verify the Inventory File "
                        exit
                    }
                
                    foreach($sp in $storagePools_json.members.getEnumerator())
                    {
                        foreach($ss in $storageSystem_json.members.getEnumerator())
                        {
                            if(($sp.name -eq $csvStoragePool ) -and ($ss.name -eq $csvStorageSystem))
                            {
                                $newVolume = [PSCustomObject]@{
                                name        = $csvvolumeName;
                                storageSystemUri = $ss.uri;
                                provisioningParameters = @{
                                    storagePoolUri    = $sp.uri;
                                    requestedCapacity = $csvcapacity;
                                    provisionType     = "Thin";
                                    shareable         = $false
                                    }
                                }
                                $response = Send-HPOVRequest -uri $Global:StorageVolumeUri POST $newVolume 
                                $responseUri = $response.uri
                                $resourceName = $csvvolumeName
                        
                                if ($responseUri -ne $null)
                                {
                                    $hashtable.Add( $responseUri,$resourceName)
                                } 
                            }
                        }
                    }
                }
            }
            elseif($selection -eq "y" -or $selection -eq "Y")
            {
                $inputData = Import-csv $volumeDetails
                foreach ($input in $inputData )
                {
                    $csvvolumeName = $input.volumeName
                    $csvVolumeTemplate = $input.VolumeTemplate
                    $csvcapacity = $input.capacity
                    if ($csvvolumeName -eq $null -or $csvcapacity -eq $null -or $csvVolumeTemplate -eq $null  )
                    {
                        Write-Host " Please verify the Inventory File "
                        writeLog " Please verify the Inventory File "
                        exit
                    }
                    foreach($vt in $volumeTemplate_json.members.getEnumerator())
                    {
                        if($vt.name -eq $csvVolumeTemplate)
                        {
                            $vtUri = $vt.uri
                            $newVolume = [PSCustomObject]@{
                                name        = $csvvolumeName;
                                templateUri        = $vtUri;
                                provisioningParameters = @{
                                    requestedCapacity = $csvcapacity;
                                    shareable         = $false
                                    }
                                }
                                $response = Send-HPOVRequest -uri $Global:StorageVolumeUri POST $newVolume
                                $responseUri = $response.uri
                                $resourceName = $csvvolumeName
                        
                                if ($responseUri -ne $null)
                                {
                                    $hashtable.Add( $responseUri,$resourceName)
                                } 
                            }
                        }        
                    }
                }
                
            taskCompletionCheck $hashtable $Global:AddVolumeErrorStatus $Global:AddVolumeSuccessStatus $state
            Write-Host "View the error report in $Global:AddVolumeErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:AddVolumeSuccessStatus"
        }
        writeLog -message "FUNCTION END : ADD STORAGE VOLUME"
    }
}

function Remove-StorageVolume
{
    <#
        Function to remove storage volume
    #>

    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$StorageVolume_List     
    )

    Process 
    {
        writeLog -message "FUNCTION BEGIN : REMOVE STORAGE VOLUME"

        CreateNewFile $Global:RemoveStorageVolumeSuccessStatus $Global:RemoveStorageVolumeErrorStatus
        $hashtable = @{}
        $State = "Removed!"
        $header = "Name,Status"
        $header | Add-Content $Global:RemoveStorageVolumeSuccessStatus
        $header | Add-Content $Global:RemoveStorageVolumeErrorStatus
        
        $StorageVolumeGet = Send-HPOVRequest -uri $Global:StorageVolumeUri GET

        if ($StorageVolume_List)
        {
            Write-Host "Deleting in Progress ... " -ForegroundColor Yellow
            writeLog "Deleting in Progress ... "
           
            $inputData = Import-csv $StorageVolume_List
            foreach ($input in $inputData )
            {
                #to import all the attributes present in the input file. 
                $csv_name = $input.Volume
                    
                if ($csv_name -eq $null)
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                if($StorageVolumeGet.members.name -contains $csv_name)
                {
                    try
                    {
                        $response = Remove-HPOVStorageVolume -storageVolume $csv_name 
                        $responseUri = $response.uri
                        $resourceName = $csv_name
                        
                        if ($responseUri -ne $null)
                        {
                            $hashtable.Add( $responseUri,$resourceName)
                        } 
                    } 
                    catch
                    {
                        $ErrorMessage = $_.Exception.Message
                        Write-Host $ErrorMessage -ForegroundColor Red
                        writeLog -message $ErrorMessage -debuglevel "ERROR"
                        $csv_name+","+$ErrorMessage | Add-Content $Global:RemoveStorageVolumeErrorStatus -Force  
                    }
                }
                else
                {
                    Write-Host "$csv_name does not exists" -ForegroundColor Red
                    writeLog "$csv_name does not exists"
                    $csv_name + "," + "Does not exists" | Add-Content $Global:RemoveStorageVolumeErrorStatus -Force 
                }
            }
            taskCompletionCheck $hashtable $Global:RemoveStorageVolumeErrorStatus $Global:RemoveStorageVolumeSuccessStatus $state
            Write-Host "View the error report in $Global:RemoveStorageVolumeErrorStatus" -ForegroundColor Red
            Write-Host "View the success report in $Global:RemoveStorageVolumeSuccessStatus" 
        }
        writeLog -message "FUNCTION END : REMOVE STORAGE VOLUME"
    }
}

function Add-EthernetNetworksBulk
{
    <#
        Function to add ethernet networks in bulk
    #> 
    Param
    (             
        [parameter(Mandatory = $true, HelpMessage = "Enter the Network name")]
        [ValidateNotNullOrEmpty()]
        [System.String]$Name,

        [parameter(Mandatory = $true, HelpMessage = "Enter the vlan range(100-120,123,135)")]
        [ValidateNotNullOrEmpty()]
        [System.String]$vlanRange
    )
    process
    {
        writeLog -message "FUNCTION BEGIN : ADD ETHERNET NETWORKS BULK"

        CreateNewFile $Global:AddEthernetNetworksBulkSuccessStaus $Global:AddEthernetNetworksBulkErrorStatus
        $state = "Added!"
        try
        {
            $ethnet = [PSCustomObject]@{
                vlanIdRange = $vlanRange;
                purpose = "General";
                namePrefix = $Name;
                smartLink = $false;
                privateNetwork =  $false;
                type = "bulk-ethernet-network";
                bandwidth = @{
                    maximumBandwidth = 10000;
                    typicalBandwidth = 2000
                    }
                }
            $response = Send-HPOVRequest -uri $Global:bulkEthernetUri POST $ethnet
            $Name+","+$state | Add-Content $Global:AddEthernetNetworksBulkSuccessStaus -Force
            Write-Host "$Name :$state"
            writeLog -message "$Name :$state"  
        }
        catch
        {
            $ErrorMessage = $_.Exception.Message
            Write-Host $ErrorMessage -ForegroundColor Red
            writeLog -message $ErrorMessage -debuglevel "ERROR"
            $Name+","+$ErrorMessage | Add-Content $Global:AddEthernetNetworksBulkErrorStatus -Force  
        }
        Write-Host "View the error report in $Global:AddEthernetNetworksBulkErrorStatus" -ForegroundColor Red
        Write-Host "View the success report in $Global:AddEthernetNetworksBulkSuccessStaus" 
        writeLog -message "FUNCTION END : ADD ETHERNET NETWORKS BULK"
    }
}













