namespace TokenMen;

internal static class Utils
{
    internal static bool Is64Bit() => IntPtr.Size == 8;
    internal static bool PrivilegeEnabler(string[] privs)
    {
        bool success = false;
        
        success = OpenProcessToken(GetCurrentProcess(), TokenAccessRights.TOKEN_ADJUST_PRIVILEGES | TokenAccessRights.TOKEN_QUERY, out IntPtr hToken);
        if (!success)
        {
            Console.WriteLine("[!] Failed to get handle to own process token");
            return false;
        }


        foreach (var priv in privs)
        {
            TOKEN_PRIVILEGES tp = new();
            tp.Privileges.Attributes = SE_PRIVILEGE_ENABLED;

            if (!LookupPrivilegeValue(null, priv, ref tp.Privileges.Luid))
            {
                Console.WriteLine("[-] Failed to find privilege. (Error: {0})", GetLastErrorString());
                CloseHandle(hToken);
                return false;
            }

             success = AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            if (!success || GetLastError() != 0)
            {
                Console.WriteLine("[-] Failed to assign priv to token. (Error: {0})", GetLastErrorString());
                CloseHandle(hToken);
                return false;
            }
        }

        CloseHandle(hToken);
        Console.WriteLine("[+] Privileges adjusted");
        return true;
    }
}
