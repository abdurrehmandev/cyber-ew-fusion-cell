Write-Host "`n===== DEV ENVIRONMENT AUDIT =====`n"

# 1️⃣ Python
Write-Host "Python Version:"
try { python --version } catch { Write-Host "Python not found" }

Write-Host "`nPip Version:"
try { python -m pip --version } catch { Write-Host "pip not found" }

Write-Host "`nPython Executables:"
try { where python } catch { Write-Host "No python executables found" }

Write-Host "`nInstalled Python Packages:"
try { python -m pip list | Select-Object -First 20 } catch { Write-Host "No pip packages found" }
Write-Host "..."

# 2️⃣ Git
Write-Host "`nGit Version:"
try { git --version } catch { Write-Host "Git not found" }

# 3️⃣ PowerShell
Write-Host "`nPowerShell Version:"
$PSVersionTable.PSVersion | Format-Table

# 4️⃣ Chocolatey
Write-Host "`nChocolatey Version:"
try { choco --version } catch { Write-Host "Chocolatey not found" }

# 5️⃣ Winget
Write-Host "`nWinget Version:"
try { winget --version } catch { Write-Host "Winget not found" }

# 6️⃣ VS Code / Visual Studio
Write-Host "`nVisual Studio Code:"
try { code --version } catch { Write-Host "VS Code not found" }

Write-Host "`nVisual Studio:"
try { & "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe" /? > $null; Write-Host "Visual Studio installed" } catch { Write-Host "Visual Studio not found" }

# 7️⃣ Node / npm
Write-Host "`nNode.js Version:"
try { node --version } catch { Write-Host "Node.js not found" }

Write-Host "npm Version:"
try { npm --version } catch { Write-Host "npm not found" }

Write-Host "`n===== END OF AUDIT =====`n"
