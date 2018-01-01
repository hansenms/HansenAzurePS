function Get-GitHubRawPath
{
    param(
        
        [Parameter(Mandatory, Position = 1)]
        [String]$File,
        
        [String]$RepoPath = ".\",
        [String]$RemoteName = "origin"
    )

    return "This is the repo: $RemoteName"
}
