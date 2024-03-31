<# 
.SYNOPSIS
A concept script to prestage a computer object with minimum permissions

.DESCRIPTION
 This script snippet aims to prestage a computer object and set the minimum permissions required to (re)join a domain.
 
 To avoid setting unecessary permissions, when prestaging the computer, we set:
 - dNSHostName value to the FQDN of the computer
 - ServicePrincipalName values for the computer
 NOTE: This script also sets the HOST/ values as well as the RestrictedKrbHost. Technically, the HOST/ entries are not required 
 As the machine will set these values itself. There is no harm in setting these values in advance.

 If these values are not set before joining, the join account will need extra permissions to set these values
 on the computer object.
 The join account is assigned the following two ACLs over the computer object:
 - Reset Password - (User-Force-Change-Password)
 - Read and Write Account Restrictions (Only really need Write)

 Once the machine has been joined, the join account can safely be removed from all permissions on the computer account.

.PARAMETER computerName
Specifies the computername that will be joined.
This is a mandatory value.

.PARAMETER domainRejoinAccountName
Specifies the accountname that will be used to perform the join.
This is a mandatory value.

.PARAMETER computerPath
Specifies the Distinguished Name of the path where the computer will be added to AD (ie; The "OU" where the computer will reside).
This is a mandatory value.

.PARAMETER DC
To avoid any possible replication issues, a DC can be specified. If ommited, the PDCEmulator is chosen.

.EXAMPLE
prestageComputer.ps1 -computerName SYSCOM1 -domainRejoinAccountName t1drejoin -computerPath 'OU=Computers,OU=Tier 1,OU=Org,DC=test,DC=local'

In this example a computer named "SYSCOM1" is to be created at the specified path. 
dNSHostname and ServicePrincipalName will be set with the required values. The account "t1drejoin" will be granted 
Reset Password and Read/Write Account Restrictions to "SYSCOM1".
#>

# Parameters --- Set accordingly or call script with parameters
param(
    [Parameter(mandatory = $true)]$computerName,
    [Parameter(mandatory = $true)]$domainRejoinAccountName,
    [Parameter(mandatory = $true)]$computerPath,
    $dc = ((Get-ADDomainController | where-object { $_.OperationMasterRoles -contains "PDCEmulator" }).hostName)
)


# Tweak your new-adcomputer command as you see fit.

write-host "Creating computer object $($computerName)"
try {
    new-adcomputer -name $computerName -Path $computerPath -KerberosEncryptionType 'AES128,AES256' -Server $DC
}
catch {
    write-host "Error trying to create computer object $($computername)"
    write-host "Please check the machine does not exist, the name and path values are correct"
    break
}

# Get the Computer Object - Loop 10 times and quit if fail.
$counter = 0
do {
    # Sleep for a moment - allow a break if this routine has to loop
    write-host "Finding $($computerName)..."
    start-sleep 2
    try {
        $objectComputer = get-adcomputer -LDAPFilter "(name=$($computerName))" -Server $DC
    }
    catch {
        write-host "Error Searching for computer object."
        break
    }
    $counter++    
} while ((-not $objectComputer) -and ($counter -lt 10))

# Proceed only if the computer object is found
if (($objectComputer)) {
    # Set FQDN Values
    $DNSFQDN = (Get-ADDomain).DNSRoot
    $ADRoot = (Get-ADDomain).distinguishedname
    $computerFQDN = "$($computerName).$($DNSFQDN)"

    # Set Computer dnsHostName (if not already set)
    if ($objectComputer.DNSHostName -ne "$($computerFQDN)") { 
        write-host "Setting dnsHostName"
        Set-ADComputer -Identity $objectComputer -DNSHostName "$($computerFQDN)" -server $DC
    }

    # Add ServicePrincipalNames (for any not already set).
    $customSPNs = @("HOST/$($computerName)", "HOST/$($computerFQDN)", "RestrictedKrbHost/$($computerName)", "RestrictedKrbHost/$($computerFQDN)")
    foreach ($customSPN in $customSPNs) {
        if ($objectComputer.ServicePrincipalNames -notcontains $customSPN) {
            write-host "Adding $($CustomSPN)"
            Set-ADComputer -Identity $objectComputer -ServicePrincipalNames @{Add = "$($customSPN)" } -Server $DC
        }
    }

    $dRejoinAccount = get-aduser -LDAPFilter ("(samaccountname=$($DomainRejoinAccountName))") -Server $DC

    if ($dRejoinAccount) {

        # MAP AD Drive
        if (-not ((Get-PSDrive) | where-object { $_.name -eq "AD" })) {
            New-PSDrive -name AD -PSProvider ActiveDirectory -Root $ADRoot -server $DC
            write-host "Mounted AD Drive."
        }
        # Get the ACL of the desired computer object      
        $ACL = Get-Acl -Path "AD:\$($objectComputer)"            
                
        # Set User-Force-Change-Password Right (Reset Password)
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule ([System.Security.Principal.IdentityReference] $dRejoinAccount.SID, "ExtendedRight", "Allow", [GUID]"00299570-246d-11d0-a768-00aa006e0529", "None", [GUID]"00000000-0000-0000-0000-000000000000" )))  
    
        # Set User-Account-Restrictions
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule ([System.Security.Principal.IdentityReference] $dRejoinAccount.SID, "ReadProperty, WriteProperty", "Allow", [GUID]"4c164200-20c0-11d0-a768-00aa006e0529", "None", [GUID]"00000000-0000-0000-0000-000000000000")))  

        # Write back the new ACL
        write-host "Setting ACLs"
        Set-Acl -Path "AD:\$($objectComputer)" -AclObject $ACL    
    }
    else {
        # Couldn't find the join account in AD
        write-host "Could not find domain rejoin account. Doing nothing."
    }
}
else {
    # Couldn't find computer object
    write-host "Couldn't find computer object in AD"
}
