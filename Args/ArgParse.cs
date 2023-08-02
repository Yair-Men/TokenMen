﻿using System.Collections.Generic;
using System.Diagnostics;

namespace Args;

public static class ArgParse
{
    public static ArgumentParserResult Parse(IEnumerable<string> args)
    {
        var arguments = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var argument in args)
            {
                var idx = argument.IndexOf(':');
                if (idx > 0)
                {
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                }
                else
                {
                    idx = argument.IndexOf('=');
                    if (idx > 0)
                    {
                        arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                    }
                    else
                    {
                        arguments[argument] = string.Empty;
                    }
                }
            }

            return ArgumentParserResult.Success(arguments);
        }
        catch (System.Exception ex)
        {
            Debug.WriteLine(ex.Message);
            return ArgumentParserResult.Failure();
        }
    }
}