function Get-GitHubRawPath
{
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

    $fullPath =  $(Get-Item $File).FullName
    $fileRelativePath = RelativePath -absolutePath $fullPath -basePath $gitTopLevel
    if ($fileRelativePath.Substring(0,2) -eq ".\") {
        $fileRelativePath = $fileRelativePath.Substring(2,$fileRelativePath.Length-2)
    }
    $fileRelativePath = $fileRelativePath -replace "\\", "/"

    try { 
        $remoteUri = $(git remote get-url $Remote) 
    } catch {
        trow "$Remote is not a remote of this repository"
    }
    
    $remoteUri = [System.Uri]$remoteUri

    if ($remoteUri.Host -ne "github.com") {
        throw "The remote URL is not a Github location"
    }

    $remotePath = $remoteUri.AbsolutePath 
    if ($remotePath.SubString($remotePath.Length-4,4) -eq '.git') {
        $remotePath = $remotePath.Substring(0,$remotePath.Length-4)
    }

    $rawHost = "https://raw.githubusercontent.com"

    $rawUrl = $rawHost + $remotePath + "/" + $(git rev-parse $Revision) + "/" + $fileRelativePath

    return $rawUrl
}

function GitAvailable
{
    $gitexists = $false

    if (Get-Command "git" -errorAction SilentlyContinue)
    {
        $gitexists = $true
    }

    return $gitexists
}

function RelativePath
{
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