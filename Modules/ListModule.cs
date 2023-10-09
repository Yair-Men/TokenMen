
using Args;
using TokenMen.ModulesOptions;

namespace TokenMen.Modules;

internal class ListModule
{
    public static void Run(ArgParser parser)
    {
        var args = parser.Parse<ListOptions>();

        Console.WriteLine("List Not implemented yet");
    }
}
