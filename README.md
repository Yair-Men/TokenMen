A simple POC tool to steal a process's token and launch a new one.

Capable of changing needed ACLs to launch a new interactive process with the privileges of a user who is not logged in interactively (Such as WinRM)

Require "SeDebugPrivilege" privilege (Mostly Local Admin after UAC), and the desired process is not PP/L protected.

Examples:

- Launch cmd with the rights of the user who runs the PID 1852
```PowerShell
.\TokenMen.exe 1852 cmd
```

- Same as above but also changes the ACL to allow running new processes interactively (ChangeACL is case-insensitive)
```PowerShell
.\TokenMen.exe 1852 cmd ChangeACL
```


TODO:
- Add the ability to restore the changed DACLs