﻿using Args;
using TokenMen.Modules;

namespace TokenMen;

public class Program
{
    public static void Main(string[] args)
    {
        
        ArgParser parser = ArgParser.Init(args, true);

        switch (parser.ModuleName.ToLower())
        {
            case "exec":
                ExecModule.Run(parser);
                break;
            case "misc":
                MiscModule.Run(parser);
                break;
            case "edit":
                EditModule.Run(parser);
                break;
            default:
                break;
        }

    }
}
