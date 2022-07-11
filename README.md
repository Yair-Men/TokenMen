# TokenMen

Duplicate A Primary Token from A running process and launch a new Process with the Duplicated Token as that user.

No needed for PsExec or other shitty ShellCode Injection stuff to "Impersonate" a login user.

Require "SeDebugPrivilege" privilege (Mostly Local Admins after UAC), and that desired proces not PP/L protected.

Example:
```PowerShell
.\TokenMen.exe 1852 cmd
```
