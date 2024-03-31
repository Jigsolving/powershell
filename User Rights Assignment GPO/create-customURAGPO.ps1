<# 
.SYNOPSIS
A concept script to create a User Rights Assignment Policy completely in PowerShell

.DESCRIPTION

WARNING !! WARNING !! WARNING !! WARNING !! WARNING !! WARNING !! WARNING !! WARNING !! WARNING !!
This script is a concept script and is not intended for production use as is and is also provided as is.
Not saying it won't work - just saying you need to test it thoroughly before using any concepts presented in this script.

There is no warranty on this script. Use at your own risk. It is intended as an exploration into an idea.

This script will actually do nothing until you remove the "Exit" line further down in the script.
Please do not test this directly in a production environment. If you're not sure, please learn how this script works 
before using it anywhere.

It has only been tested to create and link a GPO that sets a series of User Rights Assignment.

The environment was tested in July and August of 2022 using the following platforms:
Windows Server 2019 and 2022 - AD Running in 2016 Domain/Forest mode.
I can't see any reason it wouldn't work on 2012 R2+

It may work on older platforms but remember that some of the Well Known SIDs were not so well known back then :) eg; "Local Account" and 
"Local account and member of Administrators group" did not exist before then. 
NOTE: KB2871997 introduced those SIDs to the older OSes anyway, this is just an example. Hard to think of every permutation on this.

Also note that if you mess this up, you could cause damage to your environment so please - test in an isolated lab first.
FYI: It works fine for me :) 
 
This script has a number of interrelated functions and a few json strings that work together to create and link a GPO that defines specific User Rights 
Assignment and link it to a specific OU. Sequence:

1. Script is called with parameters
2. New-CustomUARGPO is called with various parameters (and subsequently utilizes helper functions)
3. If everything is valid, GPO Is created and linked or updated.

The GPO creation is achieved by:
1. Building up a file structure in a temporary folder that resembles what the "Backup-GPO" PowerShell command creates (removing any excess info)
2. To make the file structure look like the results of a "Backup-GPO", two random new GUIDs are used:       
      $BackupID = [guid]::NewGuid().toString().ToUpper()  - represents the GUID created by our imaginary Backup-GPO command
      $GPOGUID = [guid]::NewGuid().toString().ToUpper()   - represents the GUID from our imaginary GPO from our imaginary backup
   
   NOTE: These GUIDSs are only important during the import process and once imported a whole new set of GUIDs will be used by the directory that 
   received the import. 
   
3. The $UserRightsAssignment jSON string below is used to create $GPOUserRightsAssignment.
4. $GPOUserRightsAssignment is then added to the GPO's GptTmpl.inf
5. The resultant file structure is imported into AD using the import-gpo command 

6. The script then deletes the temporary file structure that was created.

NOTE: You still must import the GroupPolicy module in order to use the routine here as we make use of the "import-gpo" command.

This script is based on the write up and concepts presented here:
https://www.jigsolving.com/activedirectory/gpo-deep-dive-part-1

If you are curious as to what gets created in the file structure, simply rem out the last two lines of the New-CustomURAGPO function.

Be aware that changing the structure of any of the XML files created in this script can do VERY STRANGE things to the way items are represented in 
the GPMC.MSC console so be careful if you choose to reformat any of the $manifest_xml, $bkupInfo_xml,  $backup_xml file strings.

Some may call this a frankenscript! I like to think of it more as exploratory. :)

Some also may say that just because you can do something, doesn't mean you should.

Others may say WHY IS THIS NOT CURRENTLY POSSIBLE !?

Evaluate carefully and test, test, test!

.PARAMETER GPONamePrefix
This parameter specifies the prefix to be used for the GPO name. eg; -GPONamePrefix "Sample" would create a GPO with the name "Sample-UserRightsAssignment"
This is a mandator parameter

.PARAMETER GPOLinkOU 
This parameter specifies the Full Distinguished name of the OU where this GPO will be linked.

.Parameter GPODescription
This sets the description that will added to the GPO.
This is an optional parameter

.Parameter Server 
Specifies the domain controller to target for all activities
This is an optional parameter

.EXAMPLE
PS C:\> Create-URAGPO.ps1 -GPONamePrefix "Sample" -GPOLinkOU "OU=Sample,DC=test,DC=local" -GPODescription "New Sample GOU for URA"

In this example, a GPO is created with a name of "Sample-UserRightsAssignment" and linked to the OU of "OU=Sample,DC=test,DC=local" with a description of "New Sample GOU for URA"

.EXAMPLE

PS C:\> .\create-URAGPO.ps1 -GPONamePrefix "SpecOps" -GPOLinkOU "OU=Special,DC=test,DC=local" -GPODescription "This is our special OU restrictions Policy"

OUTPUT

BackupID: 246B56E2-992B-4CC1-BF42-8FB38755A0EB
GPOGUID: C990592D-D4CA-4875-8CCD-83BC7DA9BCC7


    Directory: C:\Users\ADMINI~1\AppData\Local\Temp\eawxtp13.hif


Mode                 LastWriteTime         Length Name                                                                                                                   
----                 -------------         ------ ----                                                                                                                   
d-----          8/6/2022   8:06 PM                {246B56E2-992B-4CC1-BF42-8FB38755A0EB}                                                                                 
> import-gpo -BackupId 246B56E2-992B-4CC1-BF42-8FB38755A0EB -Path C:\Users\ADMINI~1\AppData\Local\Temp\eawxtp13.hif -TargetName SpecOps-UserRightsAssignment -CreateIfNeeded
Linking GPO SpecOps-UserRightsAssignment to OU OU=Special,DC=test,DC=local

DisplayName   : SpecOps-UserRightsAssignment
GpoId         : ef95785a-fd86-422e-9114-66a1b896deef
Enabled       : True
Enforced      : False
Order         : 1
Target        : OU=Special,DC=test,DC=local
GpoDomainName : test.local

In the above example, a GPO called "SpecOps-UserRightsAssignment" is created and populated with the defined $userRightsAssignment json and then linked to the relevant OU.
If it had existed, it would have been overwritten with the values provided.

.NOTES
ScriptName   : Create-URAGPO.ps1
Created by   : Damien
Date Coded   : 2022/08/06

#>
param (
    [parameter(Mandatory = $true)]$GPONamePrefix,
    [parameter(Mandatory = $true)]$GPOLinkOU,
    $GPODescription,
    $server
)
#Requires -Modules ActiveDirectory
#Requires -Modules GroupPolicy

if (-not($server)) {
    $script:server = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
}
else {
    $script:Server = $server
}

#-------------------------------------------------------------------------------------------------
# $UserRightsAssignment: User Rights Assignment Privileges example json
# The following JSON lists out a few User Rights Assignments along with their description and the members to be set per right.
# You can add any of the User Rights Assignment privileges in here in the same format
# The description is not actually used in this example, but it COULD be used if you wanted to build a special group per right
# as mentioned in the loop for $GPOUserRightsAssignment within the Set-CusomtURAGPO Function which could be controlled here or within the function. 
# A full list of the User Rights Assignment Constants can be found at the end of the article here:
# https://www.jigsolving.com/activedirectory/gpo-deep-dive-part-1

Function Register-WellknownSecurityPrincipalsByNameHashTable {
<# 
.SYNOPSIS
Creates a Hash Table populated with Wellknown Security Principals Referenced by name 
as the key, accessible to the current script called $wellknownSecurityPrincipalsByName

.DESCRIPTION
The function builds a hashtable from all Well Known Principals registered within the Configuration Partition of 
Active Directory and adds extra predefined Local Well known principals if they are not already present.
The script utilizes the AD Root DSE to establish the domain's DN. By default the PDCe will be targeted unless 
Server is specified as a parameter.

Once Registered, the hash table can be queried as follows throughout the script:

PS C:\> $wellknownSecurityPrincipalsByName['Local Account']
S-1-5-113
PS C:\> $wellknownSecurityPrincipalsByName['system']
S-1-5-18

These Principals are available to be used when configuring User Rights Assignments within GPO.

.PARAMETER Server
Specifies the Domain Controller to target for this activity. If ommitted, the PDCe will be targeted by default.


.EXAMPLE
Register-WellknownSecurityPrincipalsByNameHashTable -server ADDC01.domain.local

In this example, the function targets the domaincontroller ADDC01.domain.local to retrieve information.

.NOTES
FunctionName : Register-WellknownSecurityPrincipalsByNameHashTable
Created by   : Damien
Date Coded   : 2022/08/06

#>
    param (
        $server
    )

    # $localWellKnownSecurityPrincipals: Create HashTable of some "Well Known SIDs" that just don't seem to have made it to the Configuraiton partition.
    # Interestingly, they are avaialable to use in GPMC User Rights Assignments; they resolve in GPMC but not when using the Local computer GP console (?)
    # Perhaps an oversight? Perhaps I am missing something..?
    # If you know of a way to enumerate these somehow, please let me know. :)

    $localWellKnownSecurityPrincipals = @{
        "Local account"                                    = "S-1-5-113"
        "Local account and member of Administrators group" = "S-1-5-114"
        "Restricted Code"                                  = "S-1-5-12"
        "Local Service"                                    = "S-1-5-19"
        "NT Service"                                       = "S-1-5-80"
        "All Services"                                     = "S-1-5-80-0"
        "Virtual Machines"                                 = "S-1-5-83-0"
    }

    # Set the targeted Domain Controller if $server not specified
    if (-not($server)) {  
        $server = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
    }

    # Get the Domain DN
    $domainDN = (Get-ADRootDSE -Server $server).defaultnamingcontext

    # Create empty Hashtable for $WellknownSecurityPrincipalsByName
    $script:wellknownSecurityPrincipalsByName = @{}

    # Retrieve full details of all Well Known Security Principals from the Configuration partition and store as an Object
    $rawWellknownSecurityPrincipals = get-adobject -Server $server -LDAPFilter "(&(name=*)(!objectClass=container))" -SearchBase "CN=WellKnown Security Principals,CN=Configuration,$($domainDN)" -Properties *

    # Loop through each Principal and populate the $wellknownSecurityPrincipalsByName Hash Table
    # This allows for easier lookup later
    foreach ($wellknownSecurityPrincipal in $rawWellknownSecurityPrincipals) {
        $script:wellknownSecurityPrincipalsByName[$wellknownSecurityPrincipal.Name] += $wellknownSecurityPrincipal.objectSid.value
    }

    # Add in the Local Well Known Security Principals if they do not exist
    foreach ($key in $localWellKnownSecurityPrincipals.keys) {
        if (-not($wellknownSecurityPrincipalsByName[$key])) {
            $script:wellknownSecurityPrincipalsByName.add($key, $localWellKnownSecurityPrincipals[$key])
        }
    }
}

Function UnRegister-WellknownSecurityPrincipalsByNameHashTable {
<#
.SYNOPSIS
Removes the $wellknownSecurityPrincipalsByName HashTable.

.DESCRIPTION
This is the cleanup routine for the Register-WellknownSecurityPrincipalsByNameHastTable function.
Probably overkill. Meh.

#>
   
    Remove-Variable -Name wellknownSecurityPrincipalsByName -Scope Script -ErrorAction SilentlyContinue
    
}


function Get-SIDFromName {
<#
.SYNOPSIS
Gets SID from Names; tries to resolve from AD and then searches through WellKnown Security Principals and 
returns a list in the format of:  *S-1-5-18,*S-1-5-113

.DESCRIPTION

This function is used to find SIDS from names. Multiple names can be specified. Reusltant SIDs are returned with a preceeding asterisk
These SIDs are useful when building out User Rights Assignment for a GPO.

.PARAMETER Server
Specifies the Domain Controller to target for this activity. If ommitted, the PDCe will be targeted by default.

.EXAMPLE
Get-SIDFromName -Names @('System','Local Account')

In this example, the names System and Local Account are presented as an array and the expected results would be:
*S-1-5-18,*S-1-5-113

.EXAMPLE
Get-SIDFromName -Names 'System','SomeUsernameinAD'

In this example, the names System and SomeUsernameinAD are presented as an array. They will resolve to SIDs if they exist in AD

.EXAMPLE
Get-SIDFromName "SomeUsernameinAD"

In this example, the name SomeUsernameinAD is presented as a string. It will resolve to a SID if it exists in AD


.NOTES
FunctionName : Get-SIDFromName
Created by   : Damien
Date Coded   : 2022/08/06

#>
    param (
        $names,
        $server
    )
    
    if (-not ($server)) { 
        $server = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
    }

    # Register Well known Security Principales into a hastable accessible to the script called $wellknownSecurityPrincipalsByName
    Register-WellknownSecurityPrincipalsByNameHashTable -server $server

    # Setup Regex domain removal string for later (will be used to remove Domain\ or Realm\ later)
    $regex_strip_domain = "^.*?\\"
    # Setup Regex to remove trailing comma (will be used to remove final extra comma when returning a value)
    $regex_strip_trailing_comma = ',$'

    # Set up Filter for LDAP
    $filter_LDAPUserOrComputer = "(|(ObjectClass=User)(ObjectClass=Group))"

    # Loop through the names provided to the function and return their SIDS. If the account does not exist, check its not a well known SID that has been defined in $WellKnownSIDs.
    foreach ($name in $names) {
        # Strip the domain from the name if present so we can more easily look up the value
        $commonName = $name -replace $regex_strip_domain
        
        # Look for the SID in AD
        $SID = (Get-ADObject -Server $server -ldapfilter ("(&(name=$($commonName))$($filter_LDAPUserOrComputer))") -Properties objectsid | select-object Objectsid).objectsid.value
        # If the SID was not found, try to look it up from our $wellknownSecurityPrincipalsByName Hashtable that was registered earlier.
        if (-not($SID)) { 
            $SID = $wellknownSecurityPrincipalsByName[$commonName]        
        }

        # If we have a $SID to add to our return value, add it to the end with a trailing comma
        if ($SID) {
            $returnValue = ($returnValue + ("*" + ($SID) + ","))
        }
    }   
    
    # UnRegister Well known Security Principales hastable called $wellknownSecurityPrincipalsByName
    UnRegister-WellknownSecurityPrincipalsByNameHashTable

    # Return the list of *SIDs removing any trailing comma  
    Return $returnValue -replace $regex_strip_trailing_comma
}

Function New-CustomURAGPO {
<#
.SYNOPSIS
Internal Function that actually creates the GPO based on settings. Not intended to be directly called externally.

.DESCRIPTION
This function is an internal routine that sets up a new GPO based on parameters already provided elsewhere.
It creates the temporary files responsible for the GPO and also imports the GPO.

.PARAMETER Server
Specifies the Domain Controller to target for this activity. If ommitted, the PDCe will be targeted by default.

.PARAMETER GPOName
Specifies the full name of the GPO

.PARAMETER GPTfileName
Specifies the GPTFileName to be used when creating the GPO File structure to import

.PARAMETER GPOUserRightsAssignment
User Rights Assignments to be added to the GPTFile

.PARAMETER GPOLinkOU
OU where this GPO should be linked

.PARAMETER GPODescription
Description to be added to GPO once created in ADS


.NOTES
FunctionName : New-CustomURAGPO
Created by   : Damien
Date Coded   : 2022/08/06

#>

    param(
        [parameter(Mandatory = $true)]$GPOName,         
        [parameter(Mandatory = $true)]$GPTfileName,
        [parameter(Mandatory = $true)]$GPOUserRightsAssignment,
        [parameter(Mandatory = $true)]$GPOLinkOU,
        $GPODescription,
        $server
    )

    # Owing to the way the import / backup gpo commands work, we need to get two random GUIDS to build out our new GPO.

    $BackupID = [guid]::NewGuid().toString().ToUpper()
    $GPOGUID = [guid]::NewGuid().toString().ToUpper()

    # Set the targeted Domain Controller if $server not specified
    if (-not($server)) {  
        $server = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
    }
    
    write-host "BackupID: $($BackupID)"
    write-host "GPOGUID: $($GPOGUID)"
            
    # Establish a temp folder to write out our GPO
    $Temp_Folder = ($($env:TEMP ) + "\" + [System.IO.Path]::GetRandomFileName())    
    new-item -ItemType Directory $Temp_Folder | out-null

    # Create a GPO Folder under our Temp folder to write out our GPO files for the import process
    $GPO_Folder = ($Temp_Folder + "\{" + $BackupID + "}")    
    new-item -ItemType Directory $GPO_Folder 
            
    # Set up our GPO file nmaes to create later
    $BkupinfoFileName = ($GPO_Folder + "\bkupInfo.xml")
    $ManifestFileName = ($Temp_Folder + "\manifest.xml")
    $BackupFileName = ($GPO_Folder + "\" + "backup.xml")
    $GPTFilename = ($GPO_Folder + "\" + $GPTFileName)
        
    # Create the GPT Folder where our GPO settings will be written to later
    $GPT_Folder = split-path $GPTFILEName
    new-item -ItemType Directory $GPT_Folder | out-null
    
    # Set up our file format types - this is really important because some of the files are UTF8 and one file is Unicode (UTF16-LE)
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $false
    $Utf16LEEncoding = New-Object System.Text.UnicodeEncoding

    # [Template string to build out GPO Files]-------------------------------------------------
    # The structure that gets created in a temporary folder is as follows:
    # Temp (folder):
    #   Manifest.xml
    #   GPO (Sub Folder):
    #       Backup.xml
    #       bkupInfo.xml
    #       DomainSysvol (Sub Folder):
    #            GPO (Sub folder):
    #               Machine (Sub folder):
    #                  windows nt (Sub folder):
    #                     SecEdit (Sub folder):
    #                        GptTmpl.inf
    #
    # Each of the file contents our outlined below.
    # All we do is replace values with specific variables in each of these files
    # And then we import the structure as a GPO into AD. 
    # Once imported, we delete the temporary structure. 
    # If you are playing around and want to see what is in that structure, 
    # just remove the two deletion lines towards the end of this routine and 
    # the script will leave the temp folder behild post execution.
    # 
    # XML/INF File Contents:
    #
    #
    # Manifest.xml file - $GPOGUID and $BackupID gets replaced in this file
    $manifest_xml = @"
<Backups xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest" xmlns:mfst="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest" mfst:version="1.0"><BackupInst><GPOGuid><![CDATA[{$GPOGUID}]]></GPOGuid><GPODomain/><GPODomainGuid/><GPODomainController/><BackupTime/><ID><![CDATA[{$BackupID}]]></ID><Comment/><GPODisplayName/></BackupInst><Backups/>
"@

    # BkupInfo.xml file - $BackupID gets replaced in this file
    $bkupInfo_xml = @"
<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest"><GPOGuid><![CDATA[{$GPOGUID}]]></GPOGuid><GPODomain/><GPODomainGuid/><GPODomainController/><BackupTime/><ID><![CDATA[{$BackupID}]]></ID><Comment/><GPODisplayName/></BackupInst>
"@
    
    # Backup.xml File - this Backup.XML file is specifially designed for setting up User Rights assignment only - Nothing needs replacing in this file at all.
    $backup_xml = @"
<?xml version="1.0" encoding="utf-8"?>
<!-- Copyright (c) Microsoft Corporation.  All rights reserved. -->
<GroupPolicyBackupScheme bkp:version="2.0" bkp:type="GroupPolicyBackupTemplate" xmlns:bkp="http://www.microsoft.com/GroupPolicy/GPOOperations" xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations">
    <GroupPolicyObject>
        <SecurityGroups/>
        <FilePaths/>
        <GroupPolicyCoreSettings><ID/><Domain/><SecurityDescriptor/><DisplayName/><Options/><UserVersionNumber/><MachineVersionNumber/><MachineExtensionGuids><![CDATA[[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]]]></MachineExtensionGuids><UserExtensionGuids/><WMIFilter/></GroupPolicyCoreSettings>
        <GroupPolicyExtension bkp:ID="{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}" bkp:DescName="Security">
            <FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\Microsoft\Windows NT\SecEdit\GptTmpl.inf" bkp:Location="DomainSysvol\GPO\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"/>
        </GroupPolicyExtension>
    </GroupPolicyObject>
</GroupPolicyBackupScheme>
"@

    # GptTmpl.inf File - The file containing the User Rights assignments. $GPOUserRightsAssignment variable gets replaced with our rights 
    $GPTFile = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$GPOUserRightsAssignment
"@

    #------------------------------------------------------------------------------------------------------------------------------
    # Now we have all the file data, lets write all the files to our GPO folder ensureing we are setting the encoding appropriately   
    [System.IO.File]::WriteAllLines($manifestFileName, $manifest_xml, $Utf8NoBomEncoding)
    [System.IO.File]::WriteAllLines($bkupinfoFileName, $bkupInfo_xml, $Utf8NoBomEncoding)
    [System.IO.File]::WriteAllLines($BackupFileName, $backup_xml, $Utf8NoBomEncoding)    
    [System.IO.File]::WriteAllLines($GPTFileName, $GPTFile, $Utf16LEEncoding)
    
    # Import the GPO from the files created above
        
    write-host "> import-gpo -BackupId $($backupID) -Path $($Temp_Folder) -TargetName $($GPOName) -CreateIfNeeded"
    import-gpo -BackupId $backupID -Path $Temp_Folder -TargetName $GPOName -CreateIfNeeded -Server $server | out-null

    $GPO = get-gpo -name $GPOName -Server $server
    if ($GPODescription) {            
        $GPO.Description = $GPODescription
    }
        
    write-host "Linking GPO $($GPOName) to OU $($GPOLinkOU)"
    try {
        New-GPLink -target $GPOLinkOU -Guid $GPO.id -ErrorAction Stop -Server $server
                        
    }
    catch {
        if ($PSItem.exception -like "*is already linked *") {                 
            write-host "GPO $($GPOName) Is already Linked to OU $($GPOLinkOU)"
        }
        else { throw $PSItem }
    }
        
    # Let's clean up our files and delete our temp files and our custom made temp folder. We do it this way so that it does not ask for confirmation.
    # If you have a better way to do the following two lines, feel free to fix it.
    
    attrib $manifestFileName -h
    get-childitem $Temp_Folder | remove-item -confirm:$false -Recurse
    remove-item $temp_folder -Confirm:$false -Recurse
}

# ----------- Script Starts here - To be safe, I have set the script to terminate so it will do nothing.
exit # Remove this line when you're ready to start testing in a lab first :)

# Machine GPO Extension for User Rights Assignment (URA) - Need the two GUIDs for this.
$machineExtensions = @"
[{  "Name": "Security Settings", "GUID": "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}", "DescName": "Security",
    "Path": "%GPO_MACH_FSPATH%\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf",
    "Location": "DomainSysvol\\GPO\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"      
}]
"@ | ConvertFrom-Json

# GPO Name - <$GPONamePrefix>-UserRightsAssignment
$GPOName = "$($GPONamePrefix)-UserRightsAssignment"
if (-not($GPODescription)) {
    $GPODescription = "Policy that contains user rights assignments"
}

# The filename for the GPT File we will build for importing into the new GPO (This file contains the Guts of our GPO to deny things logging in)
$GPTFileName = ($machineExtensions | Where-Object { $_.name -like "Security Settings" }).Location
 
# Build The User Rights Assignments we want for our GPO
$UserRightsAssignment = @"
{    
    "Privileges": [{
        "Name": "SeDenyNetworkLogonRight", "Description": "Deny access to this computer from the network",
        "members": ["Local Account", "Guests", "Administrator","Enterprise Admins" ]
        },{
        "Name": "SeDenyBatchLogonRight", "Description": "Deny log on as a batch job",
        "members": ["Guests", "Cryptographic Operators", "Backup Operators", "Administrators", "Administrator", "Print Operators",
                     "Server Operators", "Account Operators", "Schema Admins", "Enterprise Admins"]
        },{
        "Name": "SeDenyServiceLogonRight", "Description": "Deny log on as a service",
        "members": ["Guests", "Cryptographic Operators", "Backup Operators", "Administrators", "Administrator", "Print Operators",
                     "Server Operators", "Account Operators", "Schema Admins", "Enterprise Admins"]
        },{
        "Name": "SeDenyInteractiveLogonRight", "Description": "Deny log on locally",
        "members": ["Guests", "Account Operators", "Server Operators", "Schema Admins", "Enterprise Admins"]
        },{
        "Name": "SeDenyRemoteInteractiveLogonRight", "Description": "Deny log on through Terminal Services",
        "members": ["Local account", "Guests", "Schema Admins", "Enterprise Admins"]    
        }
    ]
}
"@ | ConvertFrom-Json


#----------------------------------------------------------------------------------------------------
# Build GPOUserRightsAssignment

$GPOUserRightsAssignment = ""
foreach ($privilege in $UserRightsAssignment.Privileges) { 
    $SIDs = $(Get-SIDFromName $privilege.members)
    # You could add a routine here to also add a custom Group per policy. eg; something like this where you make a function to getorcreatea group and return it as a  SID:
    # $SIDs = "($($SIDs), $(getOrCreateGroup -GroupPrefix $GPOPrefix -GroupSuffix $($privilege.Description) -description $( + "-" + $privilege.Description)))
    $GPOUserRightsAssignment = ($GPOUserRightsAssignment + $privilege.name + " = " + $SIDS + "`r`n")
}
    
# Make our Glorious GPO In All its splendour
New-CustomURAGPO -GPOName $GPOName -GPODescription $GPODescription -GPTfileName $GPTfileName -GPOUserRightsAssignment $GPOUserRightsAssignment -GPOLinkOU ($GPOLinkOU)
