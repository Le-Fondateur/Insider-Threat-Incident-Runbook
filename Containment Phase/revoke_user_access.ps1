# Revoke User Access PowerShell Script
# This script handles emergency access revocation for potential insider threats

# Enable strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script parameters
param(
    [Parameter(Mandatory=$true)]
    [string]$UserName,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Logs\AccessControl\",
    
    [Parameter(Mandatory=$false)]
    [string]$NotificationEmail,
    
    [Parameter(Mandatory=$false)]
    [switch]$EmergencyRevoke
)

# Initialize logging
function Initialize-Logging {
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force
    }
    $logFile = Join-Path $LogPath "access_control_$(Get-Date -Format 'yyyyMMdd').log"
    Start-Transcript -Path $logFile -Append
}

# Function to validate user exists
function Test-UserExists {
    param([string]$UserName)
    
    try {
        $user = Get-ADUser -Identity $UserName -ErrorAction Stop
        return $true
    }
    catch {
        Write-Error "User $UserName not found in Active Directory"
        return $false
    }
}

# Function to revoke Active Directory access
function Revoke-ADAccess {
    param([string]$UserName)
    
    try {
        # Disable AD account
        Disable-ADAccount -Identity $UserName
        
        # Remove from all groups except domain users
        $groups = Get-ADPrincipalGroupMembership -Identity $UserName |
            Where-Object { $_.Name -ne "Domain Users" }
        
        foreach ($group in $groups) {
            Remove-ADGroupMember -Identity $group -Members $UserName -Confirm:$false
        }
        
        Write-Host "Successfully revoked AD access for user $UserName"
        return $true
    }
    catch {
        Write-Error "Failed to revoke AD access: $_"
        return $false
    }
}

# Function to revoke file share access
function Revoke-FileShareAccess {
    param([string]$UserName)
    
    try {
        # Get all file shares
        $shares = Get-SmbShare | Where-Object { $_.Name -ne "ADMIN$" -and $_.Name -ne "IPC$" }
        
        foreach ($share in $shares) {
            # Remove access to share
            $acl = Get-Acl $share.Path
            $userAccess = $acl.Access | Where-Object { $_.IdentityReference -like "*$UserName*" }
            
            foreach ($access in $userAccess) {
                $acl.RemoveAccessRule($access)
            }
            
            Set-Acl -Path $share.Path -AclObject $acl
        }
        
        Write-Host "Successfully revoked file share access for user $UserName"
        return $true
    }
    catch {
        Write-Error "Failed to revoke file share access: $_"
        return $false
    }
}

# Function to send notification
function Send-AccessNotification {
    param(
        [string]$UserName,
        [string]$NotificationEmail,
        [hashtable]$RevokeResults
    )
    
    if (-not $NotificationEmail) { return }
    
    $body = @"
Access Revocation Report
User: $UserName
Time: $(Get-Date)

Results:
- AD Access: $($RevokeResults.AD)
- File Share Access: $($RevokeResults.FileShare)

This is an automated notification from the security system.
Please review the logs for more details.
"@

    try {
        Send-MailMessage -From "security@company.com" `
            -To $NotificationEmail `
            -Subject "SECURITY: Access Revoked for $UserName" `
            -Body $body `
            -SmtpServer "smtp.company.com"
    }
    catch {
        Write-Error "Failed to send notification: $_"
    }
}

# Main execution block
try {
    Initialize-Logging
    
    Write-Host "Starting access revocation process for user $UserName"
    
    # Validate user exists
    if (-not (Test-UserExists $UserName)) {
        throw "User validation failed"
    }
    
    # Track results
    $results = @{
        AD = $false
        FileShare = $false
    }
    
    # Revoke AD access
    $results.AD = Revoke-ADAccess -UserName $UserName
    
    # Revoke file share access
    $results.FileShare = Revoke-FileShareAccess -UserName $UserName
    
    # Send notification
    if ($NotificationEmail) {
        Send-AccessNotification -UserName $UserName -NotificationEmail $NotificationEmail -RevokeResults $results
    }
    
    # Final status
    if ($results.AD -and $results.FileShare) {
        Write-Host "Successfully completed all access revocation tasks for $UserName"
        exit 0
    }
    else {
        Write-Warning "Some revocation tasks failed. Check the logs for details."
        exit 1
    }
}
catch {
    Write-Error "Critical error during access revocation: $_"
    exit 1
}
finally {
    Stop-Transcript
}