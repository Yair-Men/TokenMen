
using Args;

namespace TokenMen.ModulesOptions;

[Module("Edit", Description = "Add or Revoke ACEs")]
internal class EditOptions
{
    [Args("trusteeName", ShortName = "n", Description = "DOMAIN\\USERNAME or SID string (if AclActions is User or Sid respectively)")]
    public string Trustee { get; set; }

    [Args("trusteeType", ShortName = "t", Description = "Either User, Sid or Everyone (Dynamic not supported in this module)", Required = true)]
    public AclActions TrusteeType { get; set; }

    [Args("action", ShortName = "a", Description = "Grant or Revoke ACEs", Required = true)]
    public EditAction Action { get; set; }

}

internal enum EditAction
{
    Grant,
    Revoke
};