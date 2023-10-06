using TokenMen;

namespace Args;

internal class ArgsOptions
{

    [Args("command", ShortName = "c", Required = true)]
    public string Command { get; set; }

    [Args("pid", ShortName = "p")]
    public uint Pid { get; set; }

    [Args("sessionId", ShortName = "si", Description = "Optional")]
    public uint SessionId { get; set; }
    
    [Args("interactive", ShortName = "it", Description = "Inject token into current process (Requires SeTcbPrivilege)")]
    public bool Interactive { get; set; }
    
    [Args("changeAcl", ShortName = "ca", Description = "Change DACLs on WorkStation and Desktop objects (When target process is not from interactive logon)")]
    public AclActions ChangeACL { get; set; }
    
    [Args("trustee", ShortName = "t", Description = "DOMAIN\\USERNAME or SID string (if AclActions is User or Sid respectively)")]
    public string Trustee { get; set; }

}