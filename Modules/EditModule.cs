using Args;
using TokenMen.ModulesOptions;

namespace TokenMen.Modules;

internal class EditModule
{
    public static void Run(ArgParser parser)
    {
        var args = parser.Parse<EditOptions>();

        if (args.TrusteeType == AclActions.Dynamic)
        {
            Console.WriteLine("[-] {0} not supported in {1}", nameof(AclActions.Dynamic), parser.ModuleName);
            return;
        }

        if (args.TrusteeType != AclActions.Everyone && String.IsNullOrEmpty(args.Trustee))
        {
            Console.WriteLine("[-] {0} requires {1}", args.TrusteeType, nameof(args.Trustee));
            return;
        }

        ACCESS_MODE accessMode = (args.Action == EditAction.Revoke) ? ACCESS_MODE.REVOKE_ACCESS : ACCESS_MODE.GRANT_ACCESS;
        Acl.Change(args.TrusteeType, args.Trustee, accessMode);
    }
}
