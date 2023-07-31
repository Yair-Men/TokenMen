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
    internal static extern uint GetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo,
        out IntPtr pSidOwner, out IntPtr pSidGroup, out IntPtr pDacl, out IntPtr pSacl, out IntPtr pSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint SetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo,
        IntPtr pSidOwner, IntPtr pSidGroup, IntPtr pDacl, IntPtr pSacl);

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
    internal static extern bool ConvertSidToStringSid(IntPtr pSid, out IntPtr strSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool ConvertStringSidToSid(string StringSid, [Out] out IntPtr ptrSid);
}

internal class WinEnums
{
    public enum WELL_KNOWN_SID_TYPE
    {
        WinNullSid = 0,
        WinWorldSid = 1,
        WinLocalSid = 2,
        WinCreatorOwnerSid = 3,
        WinCreatorGroupSid = 4,
        WinCreatorOwnerServerSid = 5,
        WinCreatorGroupServerSid = 6,
        WinNtAuthoritySid = 7,
        WinDialupSid = 8,
        WinNetworkSid = 9,
        WinBatchSid = 10,
        WinInteractiveSid = 11,
        WinServiceSid = 12,
        WinAnonymousSid = 13,
        WinProxySid = 14,
        WinEnterpriseControllersSid = 15,
        WinSelfSid = 16,
        WinAuthenticatedUserSid = 17,
        WinRestrictedCodeSid = 18,
        WinTerminalServerSid = 19,
        WinRemoteLogonIdSid = 20,
        WinLogonIdsSid = 21,
        WinLocalSystemSid = 22,
        WinLocalServiceSid = 23,
        WinNetworkServiceSid = 24,
        WinBuiltinDomainSid = 25,
        WinBuiltinAdministratorsSid = 26,
        WinBuiltinUsersSid = 27,
        WinBuiltinGuestsSid = 28,
        WinBuiltinPowerUsersSid = 29,
        WinBuiltinAccountOperatorsSid = 30,
        WinBuiltinSystemOperatorsSid = 31,
        WinBuiltinPrintOperatorsSid = 32,
        WinBuiltinBackupOperatorsSid = 33,
        WinBuiltinReplicatorSid = 34,
        WinBuiltinPreWindows2000CompatibleAccessSid = 35,
        WinBuiltinRemoteDesktopUsersSid = 36,
        WinBuiltinNetworkConfigurationOperatorsSid = 37,
        WinAccountAdministratorSid = 38,
        WinAccountGuestSid = 39,
        WinAccountKrbtgtSid = 40,
        WinAccountDomainAdminsSid = 41,
        WinAccountDomainUsersSid = 42,
        WinAccountDomainGuestsSid = 43,
        WinAccountComputersSid = 44,
        WinAccountControllersSid = 45,
        WinAccountCertAdminsSid = 46,
        WinAccountSchemaAdminsSid = 47,
        WinAccountEnterpriseAdminsSid = 48,
        WinAccountPolicyAdminsSid = 49,
        WinAccountRasAndIasServersSid = 50,
        WinNTLMAuthenticationSid = 51,
        WinDigestAuthenticationSid = 52,
        WinSChannelAuthenticationSid = 53,
        WinThisOrganizationSid = 54,
        WinOtherOrganizationSid = 55,
        WinBuiltinIncomingForestTrustBuildersSid = 56,
        WinBuiltinPerfMonitoringUsersSid = 57,
        WinBuiltinPerfLoggingUsersSid = 58,
        WinBuiltinAuthorizationAccessSid = 59,
        WinBuiltinTerminalServerLicenseServersSid = 60,
        WinBuiltinDCOMUsersSid = 61,
        WinBuiltinIUsersSid = 62,
        WinIUserSid = 63,
        WinBuiltinCryptoOperatorsSid = 64,
        WinUntrustedLabelSid = 65,
        WinLowLabelSid = 66,
        WinMediumLabelSid = 67,
        WinHighLabelSid = 68,
        WinSystemLabelSid = 69,
        WinWriteRestrictedCodeSid = 70,
        WinCreatorOwnerRightsSid = 71,
        WinCacheablePrincipalsGroupSid = 72,
        WinNonCacheablePrincipalsGroupSid = 73,
        WinEnterpriseReadonlyControllersSid = 74,
        WinAccountReadonlyControllersSid = 75,
        WinBuiltinEventLogReadersGroup = 76,
        WinNewEnterpriseReadonlyControllersSid = 77,
        WinBuiltinCertSvcDComAccessGroup = 78,
        WinMediumPlusLabelSid = 79,
        WinLocalLogonSid = 80,
        WinConsoleLogonSid = 81,
        WinThisOrganizationCertificateSid = 82,
        WinApplicationPackageAuthoritySid = 83,
        WinBuiltinAnyPackageSid = 84,
        WinCapabilityInternetClientSid = 85,
        WinCapabilityInternetClientServerSid = 86,
        WinCapabilityPrivateNetworkClientServerSid = 87,
        WinCapabilityPicturesLibrarySid = 88,
        WinCapabilityVideosLibrarySid = 89,
        WinCapabilityMusicLibrarySid = 90,
        WinCapabilityDocumentsLibrarySid = 91,
        WinCapabilitySharedUserCertificatesSid = 92,
        WinCapabilityEnterpriseAuthenticationSid = 93,
        WinCapabilityRemovableStorageSid = 94,
        WinBuiltinRDSRemoteAccessServersSid = 95,
        WinBuiltinRDSEndpointServersSid = 96,
        WinBuiltinRDSManagementServersSid = 97,
        WinUserModeDriversSid = 98,
        WinBuiltinHyperVAdminsSid = 99,
        WinAccountCloneableControllersSid = 100,
        WinBuiltinAccessControlAssistanceOperatorsSid = 101,
        WinBuiltinRemoteManagementUsersSid = 102,
        WinAuthenticationAuthorityAssertedSid = 103,
        WinAuthenticationServiceAssertedSid = 104,
        WinLocalAccountSid = 105,
        WinLocalAccountAndAdministratorSid = 106,
        WinAccountProtectedUsersSid = 107,
        WinCapabilityAppointmentsSid = 108,
        WinCapabilityContactsSid = 109,
        WinAccountDefaultSystemManagedSid = 110,
        WinBuiltinDefaultSystemManagedGroupSid = 111,
        WinBuiltinStorageReplicaAdminsSid = 112,
        WinAccountKeyAdminsSid = 113,
        WinAccountEnterpriseKeyAdminsSid = 114,
        WinAuthenticationKeyTrustSid = 115,
        WinAuthenticationKeyPropertyMFASid = 116,
        WinAuthenticationKeyPropertyAttestationSid = 117,
        WinAuthenticationFreshKeyAuthSid = 118,
        WinBuiltinDeviceOwnersSid = 119
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
}

internal class WinStrcuts
{
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

    public struct TRUSTEE
    {
        public IntPtr pMultipleTrustee;
        public uint MultipleTrusteeOperation;
        public uint TrusteeForm;
        public uint TrusteeType;
        public IntPtr ptstrName;
    }

    public struct EXPLICIT_ACCESS
    {
        public uint grfAccessPermissions;
        public uint grfAccessMode;
        public uint grfInheritance;
        public TRUSTEE Trustee;
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
