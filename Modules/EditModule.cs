using Args;
using TokenMen.ModulesOptions;

namespace TokenMen.Modules;

internal class EditModule
{
    public static void Run(ArgParser parser)
    {
        // TODO: Implemet EDIT ACEs (Either grant or revoke)
        var args = parser.Parse<EditOptions>();
        Console.WriteLine("Edit Not implemented yet");
    }
}
