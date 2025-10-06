# pc-setup-script
Automated Windows optimization and setup script

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

iwr -useb https://bit.ly/win-pc-config -OutFile $env:TEMP\optimize.ps1; & $env:TEMP\optimize.ps1
