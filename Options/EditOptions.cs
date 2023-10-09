
using Args;

namespace TokenMen.ModulesOptions;

[Module("Edit", Description = "Add or Revoke ACEs")]
internal class EditOptions
{
    [Args("trustee", ShortName = "t", Description = "DOMAIN\\USERNAME or SID string (if AclActions is User or Sid respectively)", Required = true)]
    public string Trustee { get; set; }

    [Args("action", ShortName = "a", Description = "Add or Revoke ACEs", Required = true)]
    public EditAction Action { get; set; }
}

public enum EditAction
{
    Grant,
    Revoke
};