using System.Text;

namespace TokenMen;
internal class Launcher
{
    private PROCESS_INFORMATION pi = new();
    private STARTUPINFO si = new();
    public string lpDirectory { get; set; }
    private IntPtr hDupToken { get; set; }
    private string executableToLaunch { get; set; }
    private bool interactive { get; set; }
    private uint sessId { get; set; }
    
    public Launcher(IntPtr token, string command, bool interactive, uint sessId)
    {
        si.cb = Marshal.SizeOf(si);
        hDupToken = token;
        executableToLaunch = command;
        this.interactive = interactive;
        this.sessId = sessId;

        StringBuilder sbDirectory = new(260);
        GetSystemDirectoryW(sbDirectory, (uint)sbDirectory.Capacity);
        lpDirectory = sbDirectory.ToString();
    }

    internal bool Launch()
    {
        if (interactive)
            return CurrentConsole();
        else
            return NewConsole();
    }

    private bool CurrentConsole()
    {
        bool OK = GetTokenInformation(hDupToken, TOKEN_INFORMATION_CLASS.TokenSessionId, out uint currentSessId, sizeof(uint), out uint retLen);
        if (OK)
            Console.WriteLine("[+] Duplicated token session id: {0}", currentSessId);

        /// Just a high value that would never exists as Session ID
        if (sessId != UInt32.MaxValue)
        {
            /// In interactive mode we need the new process's token session ID to be the same as our process (use tasklist/taskmgr to get the Session ID)
            /// Requires SeTcbPrivilege
            uint id = sessId; // Ugly HACK: Can't pass sessId property as ref
            OK = SetTokenInformation(hDupToken, TOKEN_INFORMATION_CLASS.TokenSessionId, ref id, sizeof(uint));
            if (OK && GetLastError() == 0)
                Console.WriteLine("[+] session id Changed successfully to {0}", sessId);
            else
            {
                Console.WriteLine("[-] SetTokenInformation failed. (Error: {0})", GetLastErrorString());
                Console.WriteLine("You may not have \"SeTcbPrivilege\"");
            }
        }

        /// If you launch PowerShell, first thing type "exit" otherwise the terminal messes up
        /// Calling process requires SE_INCREASE_QUOTA_NAME and might need SE_ASSIGNPRIMARYTOKEN_NAME (This API will auto enable it)
        bool success = CreateProcessAsUserA(hDupToken, null, executableToLaunch, IntPtr.Zero, IntPtr.Zero, false,
            0, IntPtr.Zero, lpDirectory, ref si, out pi);
        if (!success)
        {
            Console.WriteLine("[-] CreateProcessAsUser Failed. (Error: {0})", GetLastErrorString());
            Console.WriteLine("You may not have enough privileges or given Session ID doesn't match your current process's Session ID");
            Console.WriteLine("Use me again without /interactive or check the above");
            return false;
        }
        
        Console.WriteLine("[+] CreateProcessAsUser Success");
        Console.WriteLine("[!] If you launched PowerShell, first command type \"exit\"");
        return true;

    }
    private bool NewConsole()
    {
        bool CreateProcessW = CreateProcessWithTokenW(hDupToken, 0, null, executableToLaunch, 0, IntPtr.Zero, lpDirectory, ref si, out pi);
        if (!CreateProcessW)
        {
            Console.WriteLine($"[-] CreateProcessWithTokenW Failed. (Error: {GetLastErrorString()})");
            return false;
        }
        
        Console.WriteLine("[+] CreateProcessWithTokenW Success");
        return true;
    }
   
}