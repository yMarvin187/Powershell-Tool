$ErrorActionPreference = "SilentlyContinue" 
function Show-MainMenu {
    return Read-Host "`n`n`nChoose a Category:`n
    (1)`t`tChecks`n
    (2)`t`tPrograms`n
    (3)`tClean Traces`n
    (0)`t`tClose Script`n`nChoose"
}

function Show-ChecksMenu {
    return Read-Host "`n`n`nChecks Menu:`n
    (1)`tStart Check`n
    (0)`tBack to Main Menu`n`nChoose"
}

function Show-ProgramsMenu {
    return Read-Host "`n`n`nPrograms Menu:`n
    (1)`tDownload CSV File View (by NirSoft)`n
    (2)`tDownload Timeline Explorer (by Eric Zimmerman)`n
    (3)`tDownload Registry Explorer (by Eric Zimmerman)`n
    (4)`tDownload Journal Tool (by Echo)`n
    (5)`tDownload WinprefetchView (by NirSoft)`n
    (6)`tDownload System Informer (by Winsider S&S Inc.)`n
    (7)`tDownload Everything (by voidtools)`n
    (0)`tBack to Main Menu`n`nChoose"
}

function CleanTraces {
    Write-Host "`n`nCleaning traces of the Check..." -ForegroundColor yellow
    Write-Host "`rDoes not include installed programs" -ForegroundColor yellow
    Start-Sleep 1
    Get-ChildItem -Path "C:\Temp\Dump" | Remove-Item -Recurse -Force | Out-Null
    Get-ChildItem -Path "C:\Temp\Scripts" -File | Where-Object { $_.Name -ne "Menu.ps1" } | ForEach-Object { Remove-Item -Path $_.FullName -Recurse -Force } | Out-Null
    Write-Host "Traces cleaned successfully." -ForegroundColor green
    Write-Host "`n`n`tReturning to Menu in " -NoNewline 
    Write-Host "2 " -NoNewLine -ForegroundColor Magenta
    Write-Host "Seconds`n`n`n" -NoNewline
    Start-Sleep 2
}

function Unzip {
    param(
        [string]$zipFilePath,
        [string]$destinationPath
    )
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFilePath, $destinationPath)
}

do {
    Clear-Host
    $mainChoice = Show-MainMenu
    switch ($mainChoice) {
        "1" {
            do {
                Clear-Host
                $checksChoice = Show-ChecksMenu
                switch ($checksChoice) {
                    1 {
                        Write-Host "`n`nPerforming Check..." -ForegroundColor yellow
                        New-Item -Path "C:\Temp\Scripts" -ItemType Directory -Force | Out-Null
                        New-Item -Path "C:\Temp\Dump" -ItemType Directory -Force | Out-Null
                        Set-Location "C:\temp"
                        Get-ChildItem -Path "C:\Temp\Dump" | Remove-Item -Recurse -Force | Out-Null
                        Get-ChildItem -Path "C:\Temp\Scripts" -File | Where-Object { $_.Name -ne "Menu.ps1" } | ForEach-Object { Remove-Item -Path $_.FullName -Recurse -Force } | Out-Null
                        $urls = @(
                            "https://raw.githubusercontent.com/dot-sys/PCCheckv2/master/PCCheck.ps1",
                            "https://raw.githubusercontent.com/dot-sys/PCCheckv2/master/QuickMFT.ps1",
                            "https://raw.githubusercontent.com/dot-sys/PCCheckv2/master/Registry.ps1",
                            "https://raw.githubusercontent.com/dot-sys/PCCheckv2/master/SystemLogs.ps1",
                            "https://raw.githubusercontent.com/dot-sys/PCCheckv2/master/ProcDump.ps1",
                            "https://raw.githubusercontent.com/dot-sys/PCCheckv2/master/Localhost.ps1",
                            "https://raw.githubusercontent.com/dot-sys/PCCheckv2/master/Viewer.html"
                        )
                        $destinationPath = "C:\Temp\Scripts"
                        foreach ($url in $urls) {
                            $fileName = [System.IO.Path]::GetFileName($url)
                            $destinationFile = Join-Path -Path $destinationPath -ChildPath $fileName
                            Invoke-WebRequest -Uri $url -OutFile $destinationFile
                            if (Test-Path -Path $destinationFile) {
                                Write-Host "$fileName downloaded successfully."
                            } else {
                                Write-Host "Failed to download $fileName."
                            }
                        }
                        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
                        Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force
                        & "C:\Temp\Scripts\PCCheck.ps1"
                        return
                    }
                    0 { break }
                    default {
                        Write-Host "`n`nInvalid option selected. Returning to Checks Menu." -ForegroundColor red
                        Start-Sleep 3
                    }
                }
            } while ($checksChoice -ne 0)
        }
        "2" {
            do {
                Clear-Host
                $programsChoice = Show-ProgramsMenu
                switch ($programsChoice) {
                    1 {
                        Write-Host "`n`nDownloading CSVFileView..." -ForegroundColor yellow
                        (New-Object System.Net.WebClient).DownloadFile("https://www.nirsoft.net/utils/csvfileview-x64.zip", "C:\temp\dump\CSVFileView.zip")
                        Unzip -zipFilePath "C:\temp\dump\CSVFileView.zip" -destinationPath "C:\temp\dump\CSVFileView"
                        Write-Host "CSVFileView downloaded and extracted successfully. Returning to Programs Menu." -ForegroundColor green
                        Start-Sleep 5
                    }
                    2 {
                        Write-Host "`n`nDownloading Timeline Explorer..." -ForegroundColor yellow
                        (New-Object System.Net.WebClient).DownloadFile("https://download.mikestammer.com/net6/TimelineExplorer.zip", "C:\temp\dump\TimelineExplorer.zip")
                        Unzip -zipFilePath "C:\temp\dump\TimelineExplorer.zip" -destinationPath "C:\temp\dump\TimelineExplorer"
                        Write-Host "Timeline Explorer downloaded and extracted successfully. Returning to Programs Menu." -ForegroundColor green
                        Start-Sleep 5
                    }
                    3 {
                        Write-Host "`n`nDownloading Registry Explorer..." -ForegroundColor yellow
                        (New-Object System.Net.WebClient).DownloadFile("https://download.mikestammer.com/net6/RegistryExplorer.zip", "C:\temp\dump\RegistryExplorer.zip")
                        Unzip -zipFilePath "C:\temp\dump\RegistryExplorer.zip" -destinationPath "C:\temp\dump\RegistryExplorer"
                        Write-Host "Registry Explorer downloaded and extracted successfully. Returning to Programs Menu." -ForegroundColor green
                        Start-Sleep 5
                    }
                    4 {
                        Write-Host "`n`nOpening Echo Website" -ForegroundColor yellow
                        Start-Process "http://dl.echo.ac/tool/journal"
                        Write-Host "Echo Website opened. Returning to Programs Menu." -ForegroundColor green
                        Start-Sleep 5
                    }
                    5 {
                        Write-Host "`n`nDownloading WinprefetchView..." -ForegroundColor yellow
                        (New-Object System.Net.WebClient).DownloadFile("https://www.nirsoft.net/utils/winprefetchview.zip", "C:\temp\dump\WinprefetchView.zip")
                        Unzip -zipFilePath "C:\temp\dump\WinprefetchView.zip" -destinationPath "C:\temp\dump\WinprefetchView"
                        Write-Host "WinprefetchView downloaded and extracted successfully. Returning to Programs Menu." -ForegroundColor green
                        Start-Sleep 5
                    }
                    6 {
                        Write-Host "`n`nOpening System Informer Website" -ForegroundColor yellow
                        Start-Process "https://systeminformer.sourceforge.io/canary"
                        Write-Host "System Informer Website opened. Returning to Programs Menu." -ForegroundColor green
                        Start-Sleep 5
                    }
                    7 {
                        Write-Host "`n`nDownloading Everything..." -ForegroundColor yellow
                        (New-Object System.Net.WebClient).DownloadFile("https://www.voidtools.com/Everything-1.4.1.1026.x64-Setup.exe", "C:\temp\dump\Everything.exe")
                        Write-Host "Everything downloaded successfully. Returning to Programs Menu." -ForegroundColor green
                        Start-Sleep 5
                    }
                    0 { break }
                    default {
                        Write-Host "`n`nInvalid option selected. Returning to Programs Menu." -ForegroundColor red
                        Start-Sleep 3
                    }
                }                
            } while ($programsChoice -ne 0)
        }
        "clean" {
            CleanTraces
        }
        "0" {
            Write-Host "`n`nExiting script." -ForegroundColor red
            Start-Sleep 2
            Clear-Host
            return
        }
        default {
            Write-Host "`n`nInvalid option selected. Please try again." -ForegroundColor red
            Start-Sleep 2
        }
    }
} while ($mainChoice -ne 0)
