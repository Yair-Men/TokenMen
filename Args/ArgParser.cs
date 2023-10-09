using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace Args;


public class ArgParser
{
    private IEnumerable<string> RawArgs { get; }
    public Dictionary<string, string> ParsedArgsDict { get; private set; } /// Leave public getter for old school access
    private Dictionary<string, ArgsAttribute> _argsAttributesDict { get; set; } = new();
    public string ModuleName { get; } = null;
    private static IEnumerable<ModuleAttribute> ModulesList { get; set; }

    private ArgParser(IEnumerable<string> args, string moduleName = null)
    {
        RawArgs = args;
        ModuleName = moduleName;
    }

    /// <summary>
    /// First checks. If we got arguments, if this is module based program then match the given module
    /// </summary>
    /// <param name="args">The ars received from user via the CLI</param>
    /// <param name="withModule">If there are modules in the program execution flow</param>
    /// <returns>A new instace of ArgParser to be use with the parse method to populate the arguments</returns>
    public static ArgParser Init(string[] args, bool withModule = false)
    {
        ModulesList =
            from a in AppDomain.CurrentDomain.GetAssemblies()
            from t in a.GetTypes()
            let attributes = t.GetCustomAttributes(typeof(ModuleAttribute), true)
            where attributes != null && attributes.Length > 0
            let modules = attributes.Cast<ModuleAttribute>().FirstOrDefault(x => x is not null)
            select modules;

        if (args.Length == 0)
        {
            Console.WriteLine("[-] Usage: {0} {1}ARGS",
                AppDomain.CurrentDomain.FriendlyName,
                withModule ? "MODULE " : null);

            if (withModule)
                PrintModulesName(exitProgram: true);
        }

        if (!withModule)
        {
            return new ArgParser(args);
        }

        string moduleName = args[0].ToLower();
        if (!ModulesList.Any(m => m.ModuleName.ToLower() == moduleName))
        {
            Console.WriteLine("[-] No such module '{0}'", moduleName);
            if (withModule)
                PrintModulesName(exitProgram: true);
        }
#if DEBUG
        Console.WriteLine("[!] Found Module: {0}", moduleName);
#endif
        return new ArgParser(args.Skip(1), moduleName);
    }

    /// <summary>
    /// Format and prints all available modules
    /// </summary>
    /// <param name="exitProgram">Whether to terminate the program or not after printing the modules</param>
    private static void PrintModulesName(bool exitProgram = false)
    {
        Console.WriteLine("Modules:");

        foreach (var module in ModulesList)
            Console.WriteLine($"- {module.ModuleName,-10} {module.Description}");


        if (exitProgram)
            Environment.Exit(0);
    }

    /// <summary>
    /// Using generics to allow the user to delcare his arguments in whatever class he wants.
    /// This method parse the arguments and try to convert ther values to the value decalred in the arg class
    /// </summary>
    /// <typeparam name="TModuleArgs">The class with the arguments delcared with ArgAttribute</typeparam>
    /// <returns>A new instance of the class with all the params populated in the desired data type (Declared args whom not given in the CLI, are null or default)</returns>
    /// <exception cref="Exception">throws when the given class(TModuleArgs) does not contains any instance props with Attribute Args</exception>
    public TModuleArgs Parse<TModuleArgs>() where TModuleArgs : class, new()
    {

        // Get all properties (args) for current Module
        var props = typeof(TModuleArgs)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty)
            .Where(m => m.IsDefined(typeof(ArgsAttribute)));


        // Error For dev (The given class have no props decorated with ArgsAttribute)
        if (props.Count() == 0)
        {
            throw new Exception(String.Format("[-] Class '{0}' does not have any members implements '{1}'",
                typeof(TModuleArgs).FullName, nameof(ArgsAttribute)));
        }

        ParsedArgsDict = MyParser(RawArgs);

        TModuleArgs parsedArgs = new();


        /// Check if the user supplied args, exist and declared as an ArgsAttribute
        /// Convert the argument to its corresponding (ArgsAttribute) prop type, and set value
        foreach (var prop in props)
        {
            var argAttribute = prop.GetCustomAttribute<ArgsAttribute>();
            argAttribute.IsSet = false; // Double check to prevent from user to accidently set this via the attribute fields when declaring arguments

            string content = String.Empty;

            if (
                ParsedArgsDict.TryGetValue(argAttribute.LongName, out content) ||
                (argAttribute.ShortName is not null && ParsedArgsDict.TryGetValue(argAttribute.ShortName, out content))
                )
            {
                // Check if its a Nullable type. If it does, we need the underlying type or else we crash
                Type safeType = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;

                try
                {
                    if (safeType.IsEnum)
                    {
                        if (String.IsNullOrEmpty(content))
                            throw new FormatException();
                        try
                        {
                            string[] enumKeys = Enum.GetNames(safeType);

                            /// Using Contains on the Enum keys to avoid getting int/uint from the user to be parsed into a valid (or invalid) key
                            //if (enumKeys.Contains(content.ToLower()))
                            if (enumKeys.Any(x => x.ToLower() == content.ToLower()))
                                prop.SetValue(parsedArgs, Enum.Parse(safeType, content, true));
                            else
                                throw new FormatException();
                        }
                        catch
                        {
                            throw new InvalidCastException();
                        }
                    }
                    else if (safeType.Equals(typeof(Boolean))) // If we have a boolean, it is enough to have it on the CLI without any value to set as true
                    {
                        prop.SetValue(parsedArgs, true);
                    }
                    else
                    {
                        prop.SetValue(parsedArgs, Convert.ChangeType(content, safeType));
                    }
                }
                catch (Exception ex) when (ex is FormatException || ex is InvalidCastException) // We couldn't convert the argument to the desired type
                {
                    Console.WriteLine("[-] Invalid value '{0}' for argument '{1}'. (Expected type: {2}{3})",
                        content,
                        argAttribute.LongName,
                        prop.PropertyType.Name,
                        safeType.IsEnum ? " [" + string.Join(", ", Enum.GetNames(safeType)) + "]" : null);

                    Environment.Exit(0);
                }
                argAttribute.IsSet = true;
            }
            else
            {
                if (argAttribute.Required)
                {
                    Console.WriteLine($"[-] Required argument not given ({argAttribute.LongName})");
                    PrintArgsHelp<TModuleArgs>();
                    Environment.Exit(0);
                }
            }
            _argsAttributesDict.Add(prop.Name, argAttribute);
        }

        return parsedArgs;
    }

    /// <summary>
    /// Check if the argument was actually set with a valid value, to not crash at runtime.
    /// Using "Convert.ChangeType" with primitive types (Like int/uint) will set their value to 0 (If arg was not given)
    /// This is not good when 0 is actually a valid value the developer expects/checks
    /// </summary>
    /// <param name="argName">The Property (argument) name. use nameof() for ease</param>
    /// <returns></returns>
    public bool IsSet(string argName)
    {
        bool set = false;
        try
        {
            if (_argsAttributesDict.TryGetValue(argName, out ArgsAttribute a))
            {
                return a.IsSet;
            }
        }
        catch (NullReferenceException) { }

        return set;
    }


    /// <summary>
    /// Print arguments per module (or arguments of Non-modules project)
    /// </summary>
    /// <typeparam name="TModuleArgs">The aguments class</typeparam>
    public void PrintArgsHelp<TModuleArgs>()
    {
        Console.WriteLine("Arguments:");

        var moduleArgs = typeof(TModuleArgs).GetProperties().Where(x => x.IsDefined(typeof(ArgsAttribute)));
        foreach (var prop in moduleArgs)
        {
            Type safeType = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;
            var arg = prop.GetCustomAttribute<ArgsAttribute>();

            string helpFormat = String.Format("--{0}{1} ({2}) {3}",
                arg.LongName,
                arg.ShortName != null ? $", -{arg.ShortName}" : null,
                safeType.Name + (arg.Required ? ", Required" : null),
                arg.Description != null ? $"\t'{arg.Description}'" : null);

            Console.WriteLine(helpFormat);
        }
    }

    /// <summary>
    /// Parsing string[] args using regex to allow using various methods to pass arguments from cli (/arg:VALUE, /arg=VALUE, --arg VALUE, -arg VALUE)
    /// </summary>
    /// <param name="arrArgs">string array of args from cli</param>
    /// <returns>Dictionary contains the argument name as the dict key and the argument value as the dict value</returns>
    private static Dictionary<string, string> MyParser(IEnumerable<string> arrArgs)
    {
        Regex dashRx = new(@"^\-{1,2}(?<argName>[A-Za-z]{0,})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        Regex slashRx = new(@"^/(?<argName>[A-Za-z]{0,})[:=\s]", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        Dictionary<string, string> parsedArgs = new(StringComparer.OrdinalIgnoreCase);
        List<string> args = arrArgs.ToList();

        while (args.Count() != 0)
        {
            string arg = args[0].TrimStart();
            string argValue = String.Empty;
            string argName = String.Empty;

            Match dashMatch = dashRx.Match(arg); // --argument VALUE || -arg VALUE
            Match slashMatch = slashRx.Match(arg); // /arg:VALUE || /arg=VALUE

            /// When dashMatch, the value for the arg may:
            /// 1. Not set (Boolean value - just checking if it exists)
            /// 2. The value is in the same item as the key (i.e. --user "Windy" -> Same arg)
            /// 3. The value for the current arg is in the next item (i.e. --user Windy -> 2 differnet args)
            if (dashMatch.Success)
            {
                argName = dashMatch.Groups["argName"]?.Value;

                if (args.Count == 1) /// Last arg, definitely no value in the preceeding item as there is no more items
                {
                    argValue = arg.Remove(0, dashMatch.Length);
                }
                else if (dashMatch.Value.Length == arg.Length) /// Same Length means that the next arg is maybe the value of this arg key (Or not if this is only a boolean arg)
                {
                    if (!(dashRx.IsMatch(args[1]) || slashRx.IsMatch(args[1]))) /// If next item is not arg (In our arg schema)
                    {
                        argValue = args[1];
                        args.RemoveAt(0);
                    }
                }
            }
            else if (slashMatch.Success)
            {
                argName = slashMatch.Groups["argName"]?.Value;
                argValue = arg.Remove(0, slashMatch.Length);
            }
#if DEBUG
            else
            {
                Console.WriteLine("[-] No match for arg: {0}", arg);
            }
#endif   
            if (argName != String.Empty)
                parsedArgs[argName] = argValue;

            args.RemoveAt(0);
        }

        return parsedArgs;
    }


#if DEBUG
    /// <summary>
    /// Method for debugging. List all delcared props and their value as recived from CLI (or default if arg not given)
    /// </summary>
    /// <typeparam name="T">The class with the ArgAttribute arguments </typeparam>
    /// <param name="args">The parsed args</param>
    public static void PrintArgsDebug<T>(T args)
    {
        Console.WriteLine();
        var attributes = args.GetType()
           .GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.GetProperty)
           .Where(t => t.IsDefined(typeof(ArgsAttribute)));

        var sepHeader = String.Concat(Enumerable.Repeat("=", 15 + 20 + 35 + 3));
        var header = String.Format($"{"Arg Name",-15}|{"Arg Value",-20}|{"Arg Type",-35}|\n{sepHeader}");
        Console.WriteLine(header);

        foreach (var attr in attributes)
        {
            var cols = String.Format("{0,-15}|{1,-20}|{2,-35}|", attr.Name, attr.GetValue(args) ?? "null", attr.PropertyType);
            Console.WriteLine(cols);
        }
        Console.WriteLine();
    }
#endif

}