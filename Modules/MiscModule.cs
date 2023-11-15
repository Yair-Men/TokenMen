using Args;
using TokenMen.ModulesOptions;

namespace TokenMen.Modules;

internal class MiscModule
{
    public static void Run(ArgParser parser)
    {
        var args = parser.Parse<MiscOptions>();

        if (args.Id)
            Console.WriteLine("User: {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
        else if (args.Revert)
            Console.WriteLine("RevertToSelf {0}", RevertToSelf() ? "Success" : $"Failed. Error Code: {GetLastError()}");
        else
            parser.PrintArgsHelp<MiscOptions>();
    }
}
