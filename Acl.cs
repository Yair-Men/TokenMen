using System.Text.RegularExpressions;
using TokenMen.Helpers;

namespace TokenMen;

internal enum ObjectTypeName
{
    WorkStation,
    Desktop
};

internal enum ObjectTypePermission : uint
{
    // WorkStation: EnumDesktops|ReadAttributes|AccessClipboard|CreateDesktop|WriteAttributes|AccessGlobalAtoms|ExitWindows|Enumerate|ReadScreen|Delete|ReadControl|WriteDac|WriteOwner
    WorkStation = 983_935,
    Desktop = 983_551
};
internal enum DefaultSID
{
    Everyone,
    AppPackage
};

internal enum AclActions
{
    Everyone,
    Dynamic,
    Sid,
    User
};

internal class Acl
{
    //private static readonly SECURITY_INFORMATION secInfo = SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION |
    //        SECURITY_INFORMATION.SACL_SECURITY_INFORMATION | SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;

    /// <summary>
    /// Change WorkStation and Desktop ACL. aclAction -> objTrustee relation:
    /// All -> null || Dynamic -> handle for Access Token || Sid -> String Sid || User -> String contains [domain\]username
    /// </summary>
    /// <param name="aclAction"></param>
    /// <param name="objTrustee">Either hToken, string or null</param>
    /// <param name="accessMode">Whether to allow or revoke access for trustee</param>
    /// <returns></returns>
    internal static bool Change(AclActions aclAction, Object objTrustee, ACCESS_MODE accessMode = ACCESS_MODE.GRANT_ACCESS)
    {
        /// Needs SeSecurityPrivilege to change DACLs
        if (!Utils.PrivilegeEnabler(new string[] { SE_SECURITY_NAME }))
            return false;

        // TODO: In all modes but AclActions.all we need only 1 TRUSTEE and 1 EA
        // Doesn't break functionality but try to figure out how to change arr size dynamically
        var arrTrustee = new TRUSTEE[1];
        var arrEa = new EXPLICIT_ACCESS[1];
        

        IntPtr pTrusteeName = IntPtr.Zero;
        var trusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID;


        switch (aclAction)
        {
            /// Create SID for Everyone group (This case have to be first, as this is the only case where objTrustee is null and not needed)
            case AclActions.Everyone:
                pTrusteeName = SidHelpers.CreatePermissiveSid(WELL_KNOWN_SID_TYPE.WinWorldSid);
                if (pTrusteeName == IntPtr.Zero)
                    return false;

                /// If AclActions.All: We need another EA and Trustee (for AppPackage)
                Array.Resize<EXPLICIT_ACCESS>(ref arrEa, arrEa.Length + 1);
                Array.Resize<TRUSTEE>(ref arrTrustee, arrTrustee.Length + 1);

                break;

            /// objTrustee is handle to duplicated access token
            case AclActions.Dynamic:
                pTrusteeName = Helpers.SidHelpers.GetSidFromAccessToken((IntPtr)objTrustee);
                if (pTrusteeName == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get SID from token");
                    return false;
                }
                break;
            
            /// objTrustee is a string sid
            case AclActions.Sid:
                if (!Regex.IsMatch((string)objTrustee, @"^[Ss]-1-5-[\d-]*$"))
                {
                    Console.WriteLine("[-] Invalid SID string '{0}'", objTrustee);
                    return false;
                }
                if (!ConvertStringSidToSid((string)objTrustee, out pTrusteeName))
                {
                    Console.WriteLine("[-] Failed to convert string SID");
                    return false;
                }
                break;

            /// If AclActions.User: objTrustee is string contains the username. e.g: @"menty\omera" or just username (without domain prefix)
            case AclActions.User:
                if (String.IsNullOrEmpty((string)objTrustee))
                {
                    Console.WriteLine("[-] Invalid user given '{0}'", (string)objTrustee);
                    return false;
                }

                pTrusteeName = Marshal.StringToHGlobalAnsi((string)objTrustee);
                if (pTrusteeName == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to allocate space for username");
                    return false;
                }
                trusteeForm = TRUSTEE_FORM.TRUSTEE_IS_NAME;
                break;

            default:
                Console.WriteLine("[-] Got default case. (Error: {0})", GetLastErrorString());
                return false;
        }


        #region WorkStation ACL
        arrTrustee[0] = TrusteeAndEA.CreateTrustee(trusteeForm, pTrusteeName);
        arrEa[0] = TrusteeAndEA.CreateEa(arrTrustee[0], ObjectTypePermission.WorkStation, accessMode);

        if (aclAction == AclActions.Everyone)
        {
            IntPtr pAppPackageSid = SidHelpers.CreatePermissiveSid(WELL_KNOWN_SID_TYPE.WinBuiltinAnyPackageSid);
            if (pAppPackageSid == IntPtr.Zero)
                return false;

            arrTrustee[1] = TrusteeAndEA.CreateTrustee(trusteeForm, pAppPackageSid);
            arrEa[1] = TrusteeAndEA.CreateEa(arrTrustee[1], ObjectTypePermission.WorkStation, accessMode);
        }

        IntPtr hWinsta = OpenWindowStation("WinSta0", false, WRITE_DAC | READ_CONTROL);
        if (hWinsta == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to get handle to Windows Station. (Error: {0})", GetLastErrorString());
            return false;
        }

        if (!ChangeACL(hWinsta, ObjectTypeName.WorkStation, arrEa))
        {
            Console.WriteLine("[-] Failed to set Dacl on WorkStation. (Error: {0})", GetLastErrorString());
            CloseHandle(hWinsta);
            return false;
        }
        CloseHandle(hWinsta);
        #endregion WorkStation ACL


        #region Desktop ACL
        /// Only changes to grfAccessPermissions propety required to adjust for Desktop change ACL
        arrEa[0].grfAccessPermissions = (uint)ObjectTypePermission.Desktop;
        
        /// If AclActions.All, we have another TRUSTEE
        if (aclAction == AclActions.Everyone)
            arrEa[1].grfAccessPermissions = (uint)ObjectTypePermission.Desktop;

        IntPtr hDesktop = OpenDesktopA("Default", 0, false, WRITE_DAC | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS);
        if (hDesktop == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to get handle to Desktop. (Error: {0})", GetLastErrorString());
            return false;
        }

        if (!ChangeACL(hDesktop, ObjectTypeName.Desktop, arrEa))
        {
            Console.WriteLine("[-] Failed to set Dacl on Desktop. (Error: {0})", GetLastErrorString());
            CloseHandle(hDesktop);
            return false;
        }
        CloseHandle(hDesktop);
        #endregion Desktop ACL

        return true;
    }



    /// TODO: Dynamic ACL works good, make it coresponds to /changeacl:dynamic
    /// Change grfAccessMode to ACCESS_MODE.REVOKE_ACCESS to revert changes (restore acls)
    /// Change TrusteeType (i.e. TRUSTEE_TYPE.TRUSTEE_IS_DOMAIN) dynamically
    private static bool ChangeACL(IntPtr hObject, ObjectTypeName objName, EXPLICIT_ACCESS[] arrEA)
    {
        SECURITY_INFORMATION secInfo = SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION | SECURITY_INFORMATION.SACL_SECURITY_INFORMATION | SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;

        uint dwErrCode = GetSecurityInfo(hObject, SE_OBJECT_TYPE.SE_FILE_OBJECT, secInfo, out IntPtr ppSidOwner,
            out IntPtr ppSidGroup, out IntPtr ppDACL, out IntPtr ppSacl, out IntPtr ppSecurityDescriptor);
        if (dwErrCode != 0)
        {
            Console.WriteLine("[-] Failed to call GetSecurityInfo. (Error: {0})", GetLastErrorString());
            return false;
        }

        int retval = SetEntriesInAcl(arrEA.Length, arrEA, ppDACL, out IntPtr newDACL);
        if (retval != 0 || newDACL == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to call SetEntriesInAcl for {0}. (Error: {1})", objName, GetLastErrorString());
            return false;
        }
        Console.WriteLine("[+] SetEntriesInAcl for {0} Succeeded.", objName);

        uint success = SetSecurityInfo(hObject, SE_OBJECT_TYPE.SE_WINDOW_OBJECT, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, newDACL, IntPtr.Zero);
        if (success != 0)
        {
            Console.WriteLine("[-] Failed to apply ACL for {0}. (Error: {1})", objName, GetLastErrorString());
            return false;
        }

        LocalFree(ppSecurityDescriptor);
        return true;
    }
}
