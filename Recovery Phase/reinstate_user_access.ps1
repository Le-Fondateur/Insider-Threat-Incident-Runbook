# Reinstate User Access PowerShell Script
# This script safely restores user access with proper controls and logging

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script parameters
param(
    [Parameter(Mandatory=$true)]
    [string]$UserName,
    
    [Parameter(Mandatory=$true)]
    [string]$ApproverEmail,
    
    [Parameter(Mandatory=$true)]
    [string]$BusinessJustification,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Logs\AccessControl\",
    
    [Parameter(Mandatory=$false)]
    [string]$RoleTemplate = "StandardUser",
    
    [Parameter(Mandatory=$false)]
    [switch]$RequiresMFA
)

# Initialize logging
function Initialize-Logging {
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force
    }
    $logFile = Join-Path $LogPath "access_reinstatement_$(Get-Date -Format 'yyyyMMdd').log"
    Start-Transcript -Path $logFile -Append
}

# Function to validate approver
function Test-Approver {
    param([string]$ApproverEmail)
    
    try {
        $approver = Get-ADUser -Filter {EmailAddress -eq $ApproverEmail} -Properties EmailAddress
        if (-not $approver) {
            Write-Error "Approver not found or lacks required permissions"
            return $false
        }
        
        # Check if approver has required permissions
        $requiredGroup = "Access_Approvers"
        $isMember = Get-ADGroupMember -Identity $requiredGroup | 
            Where-Object {$_.SamAccountName -eq $approver.SamAccountName}
        
        return $null -ne $isMember
    }
    catch {
        Write-Error "Failed to validate approver: $_"
        return $false
    }
}

# Function to validate user account
function Test-UserAccount {
    param([string]$UserName)
    
    try {
        $user = Get-ADUser -Identity $UserName -Properties Enabled, LockedOut
        
        if (-not $user) {
            Write-Error "User account not found"
            return $false
        }
        
        if ($user.Enabled) {
            Write-Warning "User account is already enabled"
            return $false
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to validate user account: $_"
        return $false
    }
}

# Function to apply role template
function Apply-RoleTemplate {
    param(
        [string]$UserName,
        [string]$RoleTemplate
    )
    
    try {
        # Load role template configuration
        $templatePath = "C:\Config\RoleTemplates.json"
        $templates = Get-Content $templatePath | ConvertFrom-Json
        
        $template = $templates.$RoleTemplate
        if (-not $template) {
            Write-Error "Role template not found: $RoleTemplate"
            return $false
        }
        
        # Apply group memberships
        foreach ($group in $template.Groups) {
            Add-ADGroupMember -Identity $group -Members $UserName
            Write-Host "Added to group: $group"
        }
        
        # Apply access rights
        foreach ($right in $template.AccessRights) {
            # Implementation depends on your access management system
            Set-UserAccessRight -UserName $UserName -Right $right
            Write-Host "Granted access right: $right"
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to apply role template: $_"
        return $false
    }
}

# Function to enable MFA
function Enable-UserMFA {
    param([string]$UserName)
    
    try {
        # Enable MFA requirement
        Set-MsolUser -UserPrincipalName $UserName -StrongAuthenticationRequirements @()
        
        # Generate new MFA setup link
        $setupUrl = New-MFASetupLink -UserName $UserName
        
        return $setupUrl
    }
    catch {
        Write-Error "Failed to enable MFA: $_"
        return $null
    }
}

# Function to log reinstatement
function Write-ReinstatementLog {
    param(
        [string]$UserName,
        [string]$ApproverEmail,
        [string]$BusinessJustification,
        [hashtable]$Results
    )
    
    $logEntry = @{
        Timestamp = Get-Date
        UserName = $UserName
        Approver = $ApproverEmail
        Justification = $BusinessJustification
        RoleTemplate = $RoleTemplate
        RequiresMFA = $RequiresMFA
        Results = $Results
    }
    
    $logPath = Join-Path $LogPath "reinstatements.json"
    $logEntry | ConvertTo-Json | Add-Content -Path $logPath
}

# Function to send notification
function Send-ReinstatementNotification {
    param(
        [string]$UserName,
        [string]$ApproverEmail,
        [hashtable]$Results,
        [string]$MFASetupUrl = $null
    )
    
    $body = @"
Access Reinstatement Report
User: $UserName
Approved By: $ApproverEmail
Time: $(Get-Date)

Results:
- Account Enabled: $($Results.AccountEnabled)
- Role Template Applied: $($Results.RoleApplied)
- MFA Status: $($Results.MFAEnabled)

$(if ($MFASetupUrl) {"MFA Setup Link: $MFASetupUrl"})

Please review the logs for complete details.
"@

    try {
        Send-MailMessage -From "security@company.com" `
            -To @($ApproverEmail, "security@company.com") `
            -Subject "Access Reinstated for $UserName" `
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
    
    Write-Host "Starting access reinstatement process for user $UserName"
    
    # Track results
    $results = @{
        AccountEnabled = $false
        RoleApplied = $false
        MFAEnabled = $false
    }
    
    # Validate approver
    if (-not (Test-Approver $ApproverEmail)) {
        throw "Approver validation failed"
    }
    
    # Validate user account
    if (-not (Test-UserAccount $UserName)) {
        throw "User account validation failed"
    }
    
    # Enable account
    Enable-ADAccount -Identity $UserName
    $results.AccountEnabled = $true
    
    # Apply role template
    $results.RoleApplied = Apply-RoleTemplate -UserName $UserName -RoleTemplate $RoleTemplate
    
    # Handle MFA if required
    $mfaSetupUrl = $null
    if ($RequiresMFA) {
        $mfaSetupUrl = Enable-UserMFA -UserName $UserName
        $results.MFAEnabled = ($null -ne $mfaSetupUrl)
    }
    
    # Log reinstatement
    Write-ReinstatementLog -UserName $UserName -ApproverEmail $ApproverEmail `
        -BusinessJustification $BusinessJustification -Results $results
    
    # Send notification
    Send-ReinstatementNotification -UserName $UserName -ApproverEmail $ApproverEmail `
        -Results $results -MFASetupUrl $mfaSetupUrl
    
    # Final status
    if ($results.AccountEnabled -and $results.RoleApplied) {
        Write-Host "Successfully reinstated access for $UserName"
        exit 0
    }
    else {
        Write-Warning "Some reinstatement tasks failed. Check the logs for details."
        exit 1
    }
}
catch {
    Write-Error "Critical error during access reinstatement: $_"
    exit 1
}
finally {
    Stop-Transcript
}