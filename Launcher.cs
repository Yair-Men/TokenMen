using System.Text;

namespace TokenMen;
internal class Launcher
{
    private PROCESS_INFORMATION pi = new();

    private STARTUPINFO si = new();
    public string lpDirectory { get; set; }
    private IntPtr Token { get; set; }
    private string Command { get; set; }
    private bool Interactive { get; set; }
    private uint? SessId { get; set; }
    
    public Launcher(IntPtr hDupToken, string command, bool interactive, uint? sessId)
    {
        si.cb = Marshal.SizeOf(si);
        Token = hDupToken;
        Command = command;
        Interactive = interactive;
        SessId = sessId;

        StringBuilder sbDirectory = new(260);
        GetSystemDirectoryW(sbDirectory, (uint)sbDirectory.Capacity);
        lpDirectory = sbDirectory.ToString();
    }

    internal bool Launch()
    {
        if (Interactive)
            return CurrentConsole();
        else
            return NewConsole();
    }

    private bool CurrentConsole()
    {
        bool OK;
#if DEBUG
        bool OK = GetTokenInformation(Token, TOKEN_INFORMATION_CLASS.TokenSessionId, out IntPtr remoteSessId, sizeof(uint), out _);
        if (OK)
            Console.WriteLine("[+] Duplicated token session id: {0}", remoteSessId.ToInt32());
#endif
        //// Just a high value that would never exists as a Session ID
        //if (sessId != UInt32.MaxValue)
        if (SessId is not null)
        {
            /// In interactive mode we need the duplicated process's token session ID to be the same as our process (use tasklist/taskmgr to get your Session ID)
            /// So we set the SessionID in the duplicated token to match ours
            /// This change requires SeTcbPrivilege
            uint id = (uint)SessId; /// Ugly HACK: Can't pass sessId property as ref
            OK = SetTokenInformation(Token, TOKEN_INFORMATION_CLASS.TokenSessionId, ref id, sizeof(uint));
            if (OK && GetLastError() == 0)
                Console.WriteLine("[+] session id Changed successfully to {0}", SessId);
            else
            {
                Console.WriteLine("[-] SetTokenInformation failed. (Error: {0})", GetLastErrorString());
                Console.WriteLine("You may not have \"SeTcbPrivilege\"");
                /// We don't stop execution here because maybe we are on the same SessionID allready (Although don't know if it can happen)
            }
        }

        /// If you launch PowerShell, first thing type "exit" otherwise the terminal messes up
        /// Calling process requires SE_INCREASE_QUOTA_NAME and might need SE_ASSIGNPRIMARYTOKEN_NAME (This API will auto enable it)
        bool success = CreateProcessAsUserA(Token, null, Command, IntPtr.Zero, IntPtr.Zero, false,
            0, IntPtr.Zero, lpDirectory, ref si, out pi);
        if (!success)
        {
            Console.WriteLine("[-] CreateProcessAsUser Failed. (Error: {0})", GetLastErrorString());
            Console.WriteLine("You may not have enough privileges (\"SeAssignPrimaryTokenPrivilege\") or given Session ID ({0}) doesn't match your current process's Session ID", SessId);
            Console.WriteLine("Use me again without /interactive or check the errors above");
            return false;
        }
        
        Console.WriteLine("[+] CreateProcessAsUser Success (whoami will fool you. Use '[System.Security.Principal.WindowsIdentity]::GetCurrent().Name')");
        Console.WriteLine("If you launched PowerShell and it's laggy, type \"exit\" when the PS1 displayed as PowerShell");
        Console.WriteLine("Alternatively run 'rmo psreadline' or run 'powershell -NonInteractive'");
        return true;

    }
    private bool NewConsole()
    {
        bool CreateProcessW = CreateProcessWithTokenW(Token, 0, null, Command, 0, IntPtr.Zero, lpDirectory, ref si, out pi);
        if (!CreateProcessW)
        {
            Console.WriteLine($"[-] CreateProcessWithTokenW Failed. (Error: {GetLastErrorString()})");
            return false;
        }
        Console.WriteLine("[+] CreateProcessWithTokenW Success");
        
        return true;
    }
   
}