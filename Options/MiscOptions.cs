using Args;

namespace TokenMen.ModulesOptions;

[Module("Misc", Description = "Some useful methods")]
internal class MiscOptions 
{
    [Args("Id", ShortName = "i", Description = "Get real current user identity")]
    public bool Id { get; set; }

    [Args("Revert", ShortName = "r", Description = "RevertToSelf()")]
    public bool Revert { get; set; }
}
