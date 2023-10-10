using Args;


namespace TokenMen.ModulesOptions;

[Module("Exec", Description = "Steal process's token and spawn/inject a process")]
internal class ExecOptions
{
    [Args("command", ShortName = "c", Required = true)]
    public string Command { get; set; }

    [Args("pid", ShortName = "p", Required = true)]
    public uint Pid { get; set; }

    [Args("sessionId", ShortName = "si", Description = "Optional")]
    public uint SessionId { get; set; }

    [Args("interactive", ShortName = "it", Description = "Inject token into current process (Require SeTcbPrivilege)")]
    public bool Interactive { get; set; }

    [Args("changeAcl", ShortName = "ca", Description = "Add ACEs for WorkStation and Desktop objects (When target process is not from interactive logon)")]
    public AclActions ChangeACL { get; set; }

    [Args("trustee", ShortName = "t", Description = "DOMAIN\\USERNAME or SID string (if AclActions is User or Sid respectively)")]
    public string Trustee { get; set; }
}
