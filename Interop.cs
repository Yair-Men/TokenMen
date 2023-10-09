using System.ComponentModel;
using System.Text;

namespace TokenMen;

internal class WinAPI
{
    internal static string GetLastErrorString()
        => new Win32Exception(Marshal.GetLastWin32Error()).Message;
    internal static uint GetLastError()
        => (uint)Marshal.GetLastWin32Error();


    [DllImport("User32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr OpenDesktopA(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr OpenWindowStation(string lpszWinSta, bool fInherit, uint dwDesiredAccess);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(PROCESS_ACCESS processAccess, bool bInheritHandle, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr ProcessHandle, TokenAccessRights DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    internal extern static bool DuplicateTokenEx(IntPtr hExistingToken, TokenAccessRights dwDesiredAccess, IntPtr lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, [Out, In] ref LUID lpLuid);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool CreateProcessAsUserA(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
        string lpCurrentDirectory, [In, Optional] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    internal static extern IntPtr WTSOpenServerA([In] string pServerName);

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    internal static extern void WTSCloseServer([In] IntPtr hServer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern NET_API_STATUS NetUserSetInfo(string servername, string username, int level, ref USER_INFO_1003 buf, out int parm_err);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern NET_API_STATUS NetUserAdd(string servername, int level, ref USER_INFO_1 buf, out int parm_err);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern NET_API_STATUS NetGroupAddUser(string serverName, string groupName, string userName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern uint GetSystemDirectoryW([Out] StringBuilder lpBuffer, uint uSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool SetTokenInformation(IntPtr TokenHandle,TOKEN_INFORMATION_CLASS TokenInformationClass, 
        ref uint TokenInformation, uint TokenInformationLength);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool GetTokenInformation(IntPtr TokenHandle,TOKEN_INFORMATION_CLASS TokenInformationClass,
       IntPtr TokenInformation,  uint TokenInformationLength, out uint ReturnLength);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
   out IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("Kernel32.dll", SetLastError = true)]
    internal static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("Userenv.dll", SetLastError = true)]
    internal static extern bool CreateEnvironmentBlock( [Out] IntPtr lpEnvironment, [In, Optional] IntPtr hToken, [In] bool bInherit);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint GetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo,
        out IntPtr pSidOwner, out IntPtr pSidGroup, out IntPtr pDacl, out IntPtr pSacl, out IntPtr pSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint SetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo,
        IntPtr pSidOwner, IntPtr pSidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupAccountSidA([In, Optional] string lpSystemName, IntPtr Sid, [Out, Optional] StringBuilder Name, [Optional] ref uint cchName,
        [Out, Optional] StringBuilder ReferencedDomainName, [In, Out] ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorA(IntPtr SecurityDescriptor,uint RequestedStringSDRevision,
        SECURITY_INFORMATION SecurityInformation, [Out] out string StringSecurityDescriptor, [Out] out uint StringSecurityDescriptorLen);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint LookupSecurityDescriptorPartsA([Out, Optional] out IntPtr ppOwner, [Out, Optional] out IntPtr ppGroup,
        [Out, Optional] out uint pcCountOfAccessEntries, [Out, Optional] out IntPtr ppListOfAccessEntries,
        [Out, Optional] out uint pcCountOfAuditEntries, [Out, Optional] out IntPtr ppListOfAuditEntries, [In] IntPtr pSD);

    [DllImport("advapi32.dll", CharSet = CharSet.Ansi ,SetLastError = true)]
    internal static extern string GetTrusteeNameA(IntPtr PTRUSTEE_A);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool CreateWellKnownSid(WELL_KNOWN_SID_TYPE WellKnownSidType, IntPtr DomainSid, IntPtr pSid, ref uint cbSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int SetEntriesInAcl(int cCountOfExplicitEntries, ref EXPLICIT_ACCESS pListOfExplicitEntries, IntPtr OldAcl, out IntPtr NewAcl);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int SetEntriesInAcl(int cCountOfExplicitEntries, ref EXPLICIT_ACCESS[] pListOfExplicitEntries, IntPtr OldAcl, out IntPtr NewAcl);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int SetEntriesInAcl(int cCountOfExplicitEntries, EXPLICIT_ACCESS[] pListOfExplicitEntries, IntPtr OldAcl, out IntPtr NewAcl);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
    internal static extern bool ConvertSidToStringSid(IntPtr pSid, out IntPtr pStrSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool ConvertStringSidToSid(string StringSid, [Out] out IntPtr ptrSid);
}

internal class WinEnums
{
    internal enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer,
        SidTypeLabel,
        SidTypeLogonSession
    };

    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        TokenProcessTrustLevel,
        TokenPrivateNameSpace,
        TokenSingletonAttributes,
        TokenBnoIsolation,
        TokenChildProcessFlags,
        TokenIsLessPrivilegedAppContainer,
        TokenIsSandboxed,
        TokenIsAppSilo,
        MaxTokenInfoClass
    }

    public enum WELL_KNOWN_SID_TYPE
    {
        WinWorldSid = 1,
        WinBuiltinAnyPackageSid = 84,
    }

    public enum SECURITY_INFORMATION : uint
    {
        OWNER_SECURITY_INFORMATION = 0x00000001,
        GROUP_SECURITY_INFORMATION = 0x00000002,
        DACL_SECURITY_INFORMATION = 0x00000004,
        SACL_SECURITY_INFORMATION = 0x00000008,
        LABEL_SECURITY_INFORMATION = 0x00000010,
        ATTRIBUTE_SECURITY_INFORMATION = 0x00000020,
        SCOPE_SECURITY_INFORMATION = 0x00000040,
        PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080,
        ACCESS_FILTER_SECURITY_INFORMATION = 0x00000100,
        BACKUP_SECURITY_INFORMATION = 0x00010000,
        PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000,
        PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
        UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
    }

    public enum SE_OBJECT_TYPE
    {
        SE_UNKNOWN_OBJECT_TYPE,
        SE_FILE_OBJECT,
        SE_SERVICE,
        SE_PRINTER,
        SE_REGISTRY_KEY,
        SE_LMSHARE,
        SE_KERNEL_OBJECT,
        SE_WINDOW_OBJECT,
        SE_DS_OBJECT,
        SE_DS_OBJECT_ALL,
        SE_PROVIDER_DEFINED_OBJECT,
        SE_WMIGUID_OBJECT,
        SE_REGISTRY_WOW64_32KEY
    }

    public enum NET_API_STATUS : uint
    {
        NERR_Success = 0,
        NERR_InvalidComputer = 2351,
        NERR_NotPrimary = 2226,
        NERR_SpeGroupOp = 2234,
        NERR_LastAdmin = 2452,
        NERR_BadPassword = 2203,
        NERR_PasswordTooShort = 2245,
        NERR_UserNotFound = 2221,
        ERROR_ACCESS_DENIED = 5,
        ERROR_NOT_ENOUGH_MEMORY = 8,
        ERROR_INVALID_PARAMETER = 87,
        ERROR_INVALID_NAME = 123,
        ERROR_INVALID_LEVEL = 124,
        ERROR_MORE_DATA = 234,
        ERROR_SESSION_CREDENTIAL_CONFLICT = 1219,
        RPC_S_SERVER_UNAVAILABLE = 2147944122, // 0x800706BA
        RPC_E_REMOTE_DISABLED = 2147549468 // 0x8001011C
    }


    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const int SE_PRIVILEGE_REMOVED = 0x00000004;

    #region SE_PRIVILEGE
    internal const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
    internal const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
    internal const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
    internal const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
    internal const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";
    internal const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
    internal const string SE_TCB_NAME = "SeTcbPrivilege";
    internal const string SE_SECURITY_NAME = "SeSecurityPrivilege";
    internal const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
    internal const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
    internal const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
    internal const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
    internal const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
    internal const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
    internal const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
    internal const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
    internal const string SE_BACKUP_NAME = "SeBackupPrivilege";
    internal const string SE_RESTORE_NAME = "SeRestorePrivilege";
    internal const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
    internal const string SE_DEBUG_NAME = "SeDebugPrivilege";
    internal const string SE_AUDIT_NAME = "SeAuditPrivilege";
    internal const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
    internal const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
    internal const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
    internal const string SE_UNDOCK_NAME = "SeUndockPrivilege";
    internal const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
    internal const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
    internal const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
    internal const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
    internal const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
    internal const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
    internal const string SE_RELABEL_NAME = "SeRelabelPrivilege";
    internal const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
    internal const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
    internal const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";
    internal const string SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME = "SeDelegateSessionUserImpersonatePrivilege";
    #endregion SE_PRIVILEGE


    const int STANDARD_RIGHTS_REQUIRED = 0x000F0000;
    const int SYNCHRONIZE = 0x00100000;

    [Flags]
    public enum TokenAccessRights : int
    {
        TOKEN_ADJUST_DEFAULT = 0x0080,
        TOKEN_ADJUST_GROUPS = 0x0040,
        TOKEN_ADJUST_PRIVILEGES = 0x0020,
        TOKEN_ADJUST_SESSIONID = 0x0100,
        TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_DUPLICATE = 0x0002,
        TOKEN_EXECUTE = 0x00020000,
        TOKEN_IMPERSONATE = 0x0004,
        TOKEN_QUERY = 0x0008,
        TOKEN_QUERY_SOURCE = 0x0010,
        TOKEN_READ = (0x00020000 | TOKEN_QUERY),
        TOKEN_WRITE = (0x00020000 | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT),
        TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID)
    }

    [Flags]
    public enum PROCESS_ACCESS : int
    {
        PROCESS_TERMINATE = 0x0001,
        PROCESS_CREATE_THREAD = 0x0002,
        PROCESS_SET_SESSIONID = 0x0004,
        PROCESS_VM_OPERATION = 0x0008,
        PROCESS_VM_READ = 0x0010,
        PROCESS_VM_WRITE = 0x0020,
        PROCESS_DUP_HANDLE = 0x0040,
        PROCESS_CREATE_PROCESS = 0x0080,
        PROCESS_SET_QUOTA = 0x0100,
        PROCESS_SET_INFORMATION = 0x0200,
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_SUSPEND_RESUME = 0x0800,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
        PROCESS_SET_LIMITED_INFORMATION = 0x2000,
        PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
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

    internal static readonly uint WRITE_DAC = 0x00040000;
    internal static readonly uint READ_CONTROL = 0x00020000;
    internal static readonly uint DESKTOP_READOBJECTS = 0x0001;
    internal static readonly uint DESKTOP_WRITEOBJECTS = 0x0080;
}

internal class WinStrcuts
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr pSID;
        public uint Attributes;
    }

    public struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    public struct SID_IDENTIFIER_AUTHORITY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Value;

        public SID_IDENTIFIER_AUTHORITY(byte[] value)
        {
            Value = value;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_1
    {
        public string usri1_name;
        public string usri1_password;
        public int usri1_password_age;
        public int usri1_priv;
        public string usri1_home_dir;
        public string usri1_comment;
        public int usri1_flags;
        public string usri1_script_path;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_1003
    {
        public string sPassword;
    }

    public struct ACL
    {
        public byte AclRevision;
        public byte Sbz1;
        public byte AclSize;
        public byte AceCount;
        public byte Sbz2;
    }

    public enum TRUSTEE_FORM : uint
    {
        TRUSTEE_IS_SID,
        TRUSTEE_IS_NAME,
        TRUSTEE_BAD_FORM,
        TRUSTEE_IS_OBJECTS_AND_SID,
        TRUSTEE_IS_OBJECTS_AND_NAME
    };

    public enum TRUSTEE_TYPE : uint
    {
        TRUSTEE_IS_UNKNOWN,
        TRUSTEE_IS_USER,
        TRUSTEE_IS_GROUP,
        TRUSTEE_IS_DOMAIN,
        TRUSTEE_IS_ALIAS,
        TRUSTEE_IS_WELL_KNOWN_GROUP,
        TRUSTEE_IS_DELETED,
        TRUSTEE_IS_INVALID,
        TRUSTEE_IS_COMPUTER
    };

    public enum MULTIPLE_TRUSTEE_OPERATION : uint
    {
        NO_MULTIPLE_TRUSTEE,
        TRUSTEE_IS_IMPERSONATE
    };

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct TRUSTEE
    {
        public IntPtr pMultipleTrustee;
        public MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
        public TRUSTEE_FORM TrusteeForm;
        public TRUSTEE_TYPE TrusteeType;
        public IntPtr ptstrName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 0)]
    public struct TRUSTEE_A
    {
        public IntPtr pMultipleTrustee;
        public MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
        public TRUSTEE_FORM TrusteeForm;
        public TRUSTEE_TYPE TrusteeType;
        private IntPtr ptstrName;
        public string strName => Marshal.PtrToStringAnsi(ptstrName);
    }

    public enum ACCESS_MODE : uint
    {
        NOT_USED_ACCESS,
        GRANT_ACCESS,
        SET_ACCESS,
        DENY_ACCESS,
        REVOKE_ACCESS,
        SET_AUDIT_SUCCESS,
        SET_AUDIT_FAILURE
    };

    [StructLayout (LayoutKind.Sequential, Pack = 0)]
    public struct EXPLICIT_ACCESS
    {
        public uint grfAccessPermissions;
        public ACCESS_MODE grfAccessMode;
        public uint grfInheritance;
        public TRUSTEE Trustee;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 0)]
    public struct EXPLICIT_ACCESS_A
    {
        public uint grfAccessPermissions;
        public ACCESS_MODE grfAccessMode;
        public uint grfInheritance;
        public TRUSTEE_A Trustee;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID_AND_ATTRIBUTES
    {
        [MarshalAs(UnmanagedType.Struct, MarshalTypeRef = typeof(LUID))]
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        [MarshalAs(UnmanagedType.U4)]
        public uint PrivilegeCount;

        [MarshalAs(UnmanagedType.Struct)]
        public LUID_AND_ATTRIBUTES Privileges;

        public TOKEN_PRIVILEGES()
        {
            PrivilegeCount = 1;
            Privileges = new LUID_AND_ATTRIBUTES();
        }
    }

    
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

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
}
