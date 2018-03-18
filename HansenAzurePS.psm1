function Get-GitHubRawPath {
    param(
        
        [Parameter(Mandatory, Position = 1)]
        [String]$File,
        
        [String]$RepoPath = ".\",
        [String]$Remote = "origin",
        [String]$Revision = "HEAD"
    )

    if (-not $(GitAvailable)) {
        throw "Git is not installed"
    }

    $gitTopLevel = $(git rev-parse --show-toplevel)
    if ([String]::IsNullOrEmpty($gitTopLevel)) {
        throw "Current path is not a git repository"
    }

    $fullPath = $(Get-Item $File).FullName
    $fileRelativePath = RelativePath -absolutePath $fullPath -basePath $gitTopLevel
    if ($fileRelativePath.Substring(0, 2) -eq ".\") {
        $fileRelativePath = $fileRelativePath.Substring(2, $fileRelativePath.Length - 2)
    }
    $fileRelativePath = $fileRelativePath -replace "\\", "/"

    try { 
        $remoteUri = $(git remote get-url $Remote) 
    }
    catch {
        trow "$Remote is not a remote of this repository"
    }
    
    $remoteUri = [System.Uri]$remoteUri

    if ($remoteUri.Host -ne "github.com") {
        throw "The remote URL is not a Github location"
    }

    $remotePath = $remoteUri.AbsolutePath 
    if ($remotePath.SubString($remotePath.Length - 4, 4) -eq '.git') {
        $remotePath = $remotePath.Substring(0, $remotePath.Length - 4)
    }

    $rawHost = "https://raw.githubusercontent.com"

    $rawUrl = $rawHost + $remotePath + "/" + $(git rev-parse $Revision) + "/" + $fileRelativePath

    return $rawUrl
}

function Remove-RecoveryServicesVault {
    param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceGroupName,

        [Parameter(Mandatory = $true, Position = 2)]
        [String]$VaultName,

        [Parameter(Mandatory = $false, Position = 3)]
        [String]$EnvironmentName
    )

    if ([string]::IsNullOrEmpty($(Get-AzureRmContext).Account)) {
        if ([string]::IsNullOrEmpty($EnvironmentName)) {
            Login-AzureRmAccount
        }
        else {
            Login-AzureRmAccount -Environment $EnvironmentName        
        }
    }

    $rv = Get-AzureRmRecoveryServicesVault -Name $VaultName -ResourceGroupName $ResourceGroupName

    if ($rv -eq $null) {
        Write-Host "Recovery Service Vault Not Found"
        exit 1
    }

    Set-AzureRmRecoveryServicesVaultContext -Vault $rv
    $rcs = Get-AzureRmRecoveryServicesBackupContainer -ContainerType AzureVM

    foreach ($c in $rcs) {
        $bi = Get-AzureRmRecoveryServicesBackupItem -Container $c -WorkloadType AzureVM
        Disable-AzureRmRecoveryServicesBackupProtection -Item $bi -RemoveRecoveryPoints -Force
    }

    Remove-AzureRmRecoveryServicesVault -Vault $rv
}

function New-AppRegForAADAuth {
    param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [System.Uri]$SiteUri,
    
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet("AzureCloud", "AzureUsGovernment", "AzureGermanCloud", "AzureChinaCloud")]
        [String]$Environment = "AzureCloud",

        [Parameter(Mandatory = $false, Position = 3)]
        [String]$Password,

        [Parameter(Mandatory = $false)]
        [String[]]$AADDelegatePermissions = @("User.Read"),

        [Parameter(Mandatory = $false)]
        [String[]]$GraphDelegatePermissions = @("User.Read", "User.ReadBasic.All")
        
    )

    <#

    More details at: http://blog.octavie.nl/index.php/2017/09/19/create-azure-ad-app-registration-with-powershell-part-2

    Finding information about App Permissions and Delegated Permissions:

    1. Locate the ServicePrincipal (API) you need to access, e.g.:
        
        PS> $svcPrincipal = Get-AzureADServicePrincipal -SearchString "Windows azure active directory"
        PS> $svcPrincipal

        ObjectId                             AppId                                DisplayName
        --------                             -----                                -----------
        d80f4d2b-d115-44ad-b39e-69ebdbe6c9fe 00000002-0000-0000-c000-000000000000 Windows Azure Active Directory

    2. List App Permissions:

        PS> $svcPrincipal.AppRoles | FT Id, Value, DisplayName

        Id                                   Value                         DisplayName
        --                                   -----                         -----------
        5778995a-e1bf-45b8-affa-663a9f3f4d04 Directory.Read.All            Read directory data
        abefe9df-d5a9-41c6-a60b-27b38eac3efb Domain.ReadWrite.All          Read and write domains
        78c8a3c8-a07e-4b9e-af1b-b5ccab50a175 Directory.ReadWrite.All       Read and write directory data
        1138cb37-bd11-4084-a2b7-9f71582aeddb Device.ReadWrite.All          Read and write devices
        9728c0c4-a06b-4e0e-8d1b-3d694e8ec207 Member.Read.Hidden            Read all hidden memberships
        824c81eb-e3f8-4ee6-8f6d-de7f50d565b7 Application.ReadWrite.OwnedBy Manage apps that this app creates or owns
        1cda74f2-2616-4834-b122-5cb1b07f8a59 Application.ReadWrite.All     Read and write all applications
        aaff0dfd-0295-48b6-a5cc-9f465bc87928 Domain.ReadWrite.All          Read and write domains

    3. List Delegated Permissions:

        PS> $svcPrincipal.Oauth2Permissions | FT Id, Value, UserConsentDisplayName

        Id                                   Value                      UserConsentDisplayName
        --                                   -----                      ----------------------
        a42657d6-7f20-40e3-b6f0-cee03008a62a Directory.AccessAsUser.All Access the directory as you
        5778995a-e1bf-45b8-affa-663a9f3f4d04 Directory.Read.All         Read directory data
        78c8a3c8-a07e-4b9e-af1b-b5ccab50a175 Directory.ReadWrite.All    Read and write directory data
        970d6fa6-214a-4a9b-8513-08fad511e2fd Group.ReadWrite.All        Read and write all groups
        6234d376-f627-4f0f-90e0-dff25c5211a3 Group.Read.All             Read all groups
        c582532d-9d9e-43bd-a97c-2667a28ce295 User.Read.All              Read all user's full profiles
        cba73afc-7f69-4d86-8450-4978e04ecd1a User.ReadBasic.All         Read all user's basic profiles
        311a71cc-e848-46a1-bdf8-97ff7156d8e6 User.Read                  Sign you in and read your profile
        2d05a661-f651-4d57-a595-489c91eda336 Member.Read.Hidden         Read your hidden memberships
#>

    $aadConnection = Connect-AzureAD -AzureEnvironmentName $Environment

    if ([string]::IsNullOrEmpty($Password)) {
        $Password = [System.Convert]::ToBase64String($([guid]::NewGuid()).ToByteArray())
    }

    $Guid = New-Guid
    $startDate = Get-Date     
    $PasswordCredential = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordCredential
    $PasswordCredential.StartDate = $startDate
    $PasswordCredential.EndDate = $startDate.AddYears(1)
    $PasswordCredential.Value = $Password

    $displayName = $SiteUri.Host
    [string[]]$replyUrl = $SiteUri.AbsoluteUri + ".auth/login/aad/callback"

    #AAD Permissions
    $reqAAD = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $reqAAD.ResourceAppId = "00000002-0000-0000-c000-000000000000" #See above on how to find GUIDs

    $svcPrincipal = $(Get-AzureADServicePrincipal -SearchString "Windows azure active directory") | Where-Object {$_.AppId -eq "00000002-0000-0000-c000-000000000000"}
    foreach ($perm in $AADDelegatePermissions) {
        $permId = $($svcPrincipal.Oauth2Permissions | Where-Object { $_.Value -eq $perm}).Id
        $delPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permId, "Scope"
        if ([String]::IsNullOrEmpty($reqAAD.ResourceAccess)) {
            $reqAAD.ResourceAccess = $delPermission1    
        } else {
            $reqAAD.ResourceAccess += $delPermission1
        }
    }

    #Graph Permissions
    $reqGraph1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $reqGraph1.ResourceAppId = "00000003-0000-0000-c000-000000000000" #See above on how to find GUIDs 

    $svcPrincipal = $(Get-AzureADServicePrincipal -SearchString "Microsoft Graph") | Where-Object {$_.AppId -eq "00000003-0000-0000-c000-000000000000"}
    foreach ($perm in $GraphDelegatePermissions) {
        $permId = $($svcPrincipal.Oauth2Permissions | Where-Object { $_.Value -eq $perm}).Id
        $delPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permId, "Scope" 
        if ([String]::IsNullOrEmpty($reqGraph1.ResourceAccess)) {
            $reqGraph1.ResourceAccess = $delPermission1    
        } else {
            $reqGraph1.ResourceAccess += $delPermission1
        }
    }

    $appReg = New-AzureADApplication -DisplayName $displayName -IdentifierUris $SiteUri -Homepage $SiteUri -ReplyUrls $replyUrl -PasswordCredential $PasswordCredential -RequiredResourceAccess $reqAAD, $reqGraph1

    $loginBaseUrl = $(Get-AzureRmEnvironment -Name $Environment).ActiveDirectoryAuthority

    #Small inconsistency for US gov in current AzureRm module
    if ($loginBaseUrl -eq "https://login-us.microsoftonline.com/") {
        $loginBaseUrl = "https://login.microsoftonline.us/"
    }

    $issuerUrl = $loginBaseUrl + $aadConnection.Tenant.Id.Guid + "/"

    return @{ 'IssuerUrl' = $issuerUrl
        'ClientId' = $appReg.AppId 
        'ClientSecret' = $Password
    }
}

function Set-WebAppAADAuth {
    param(

        # Parameter help description
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]$WebAppName,

        [Parameter(Mandatory = $true, Position = 3)]
        [string]$ClientId,

        [Parameter(Mandatory = $true, Position = 4)]
        [string]$ClientSecret,

        [Parameter(Mandatory = $true, Position = 4)]
        [string]$IssuerUrl,
    
        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet("AzureCloud", "AzureUsGovernment", "AzureGermanCloud", "AzureChinaCloud")]
        [String]$Environment = "AzureCloud"
    )

    $azcontext = Get-AzureRmContext
    if ([string]::IsNullOrEmpty($azcontext.Account) -or
        !($azcontext.Environment.Name -eq $Environment)) {
        Login-AzureRmAccount -Environment $Environment        
    }
    $azcontext = Get-AzureRmContext

    $authResourceName = $WebAppName + "/authsettings"
    $auth = Invoke-AzureRmResourceAction -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Web/sites/config -ResourceName $authResourceName -Action list -ApiVersion 2016-08-01 -Force

    $auth.properties.enabled = "True"
    $auth.properties.unauthenticatedClientAction = "RedirectToLoginPage"
    $auth.properties.tokenStoreEnabled = "True"
    $auth.properties.defaultProvider = "AzureActiveDirectory"
    $auth.properties.isAadAutoProvisioned = "False"
    $auth.properties.clientId = $ClientId
    $auth.properties.clientSecret = $ClientSecret
    $auth.properties.issuer = $IssuerUrl
    $auth.properties.additionalLoginParams = @( "resource=https://graph.microsoft.com" )

    New-AzureRmResource -PropertyObject $auth.properties -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Web/sites/config -ResourceName $authResourceName -ApiVersion 2016-08-01 -Force
}

function Get-AzureBearerToken {
    param(    
        [Parameter(Mandatory = $false)]
        [ValidateSet("AzureCloud", "AzureUsGovernment", "AzureGermanCloud", "AzureChinaCloud")]
        [String]$Environment = "AzureCloud"
    )

    # Inspiration for this function from:
    # - ArmClient: https://github.com/projectkudu/ARMClient
    # - https://www.deployazure.com/security/identity/authenticating-to-the-azure-resource-manager-api/
    # - https://www.bizbert.com/bizbert/2015/07/08/SettingUpPostManToCallTheAzureManagementAPIs.aspx
    # - https://gallery.technet.microsoft.com/Get-Azure-AD-Bearer-Token-37f3be03

    $azcontext = Get-AzureRmContext
    if ([string]::IsNullOrEmpty($azcontext.Account) -or
        !($azcontext.Environment.Name -eq $Environment)) {
        $azcontext = Login-AzureRmAccount -Environment $Environment        
    }
    $azcontext = Get-AzureRmContext
    $azenvironment = Get-AzureRmEnvironment -Name $azcontext.Environment

    # Load ADAL Assemblies
    $adal = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
    $ignore = [System.Reflection.Assembly]::LoadFrom($adal)
    $ignore = [System.Reflection.Assembly]::LoadFrom($adalforms)

    $adTenant = $azcontext.Tenant.Id

    $authority = $azenvironment.ActiveDirectoryAuthority + $adTenant
    $resourceAppIdURI = $azenvironment.ResourceManagerUrl

    # ClientId and Redirect URL
    # Can be found in ArmClient code or with AzureAD:
    # PS> Connect-AzureAD
    # PS> $sp = Get-AzureADServicePrincipal -SearchString "Microsoft Azure PowerShell"
    # PS> $sp.AppId
    #  1950a258-227b-4e31-a9cf-717495945fc2
    # PS> $sp.ReplyUrls
    #  urn:ietf:wg:oauth:2.0:oob

    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    # Create Authentication Context tied to Azure AD Tenant
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # Acquire token
    $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri, "Auto")

    # Create Authorization Header
    $authHeader = $authResult.CreateAuthorizationHeader()

    #Remove "Bearer " and return token
    $token = $authHeader.Substring(7)

    return @{
        'managementUrl' = $azenvironment.ResourceManagerUrl
        'bearerToken' = $token 
        'tenantId' = $adTenant
    }
}

function GitAvailable {
    $gitexists = $false

    if (Get-Command "git" -errorAction SilentlyContinue) {
        $gitexists = $true
    }

    return $gitexists
}

function RelativePath {
    param(
        [String]$absolutePath,
        [String]$basePath
    )

    $currentLoc = Get-Location
    Set-Location $basePath
    $relPath = Resolve-Path $absolutePath -Relative
    Set-Location $currentLoc
    return $relPath
}