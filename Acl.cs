namespace TokenMen;

internal class Acl
{
    internal static bool ChangeDesktopACL()
    {
        // Enable SeSecurityPrivilege
        if (!Utils.PrivilegeEnabler(new string[] { SE_SECURITY_NAME }))
            return false;

        uint WRITE_DAC = 0x00040000;
        uint READ_CONTROL = 0x00020000;
        uint DESKTOP_READOBJECTS = 0x0001;
        uint DESKTOP_WRITEOBJECTS = 0x0080;

        //IntPtr WindowStationStr = Marshal.StringToHGlobalUni("WinSta0");
        //HANDLE hWinsta = OpenWindowStation(WindowStationStr, false, 17170432);
        IntPtr hWinsta = OpenWindowStation("WinSta0", false, WRITE_DAC | READ_CONTROL);

        if (hWinsta == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to get handle to Windows Station. (Error: {0})", GetLastErrorString());
            return false;
        }

        if (!DekstopACLtoAll(hWinsta, "WorkStation"))
        {
            Console.WriteLine("[-] Failed to set Dacl on WorkStation. (Error: {0})", GetLastErrorString());
            CloseHandle(hWinsta);
            return false;
        }

        IntPtr hDesktop = OpenDesktopA("Default", 0, false, WRITE_DAC | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS);
        if (hDesktop == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to get handle to Desktop. (Error: {0})", GetLastErrorString());
            CloseHandle(hWinsta);
            return false;
        }

        if (!DekstopACLtoAll(hDesktop, "Desktop"))
        {
            Console.WriteLine("[-] Failed to set Dacl on Desktop. (Error: {0})", GetLastErrorString());
            CloseHandle(hDesktop);
            return false;
        }

        CloseHandle(hDesktop);
        CloseHandle(hWinsta);

        return true;
    }

    private static bool DekstopACLtoAll(IntPtr hObject, string objName)
    {
        SECURITY_INFORMATION secInfo = SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION | SECURITY_INFORMATION.SACL_SECURITY_INFORMATION | SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;

        uint dwErrCode = GetSecurityInfo(hObject, SE_OBJECT_TYPE.SE_FILE_OBJECT, secInfo, out IntPtr ppSidOwner, out IntPtr ppSidGroup,
            out IntPtr ppDacl, out IntPtr ppSacl, out IntPtr ppSecurityDescriptor);

        if (dwErrCode != 0)
        {
            Console.WriteLine("[-] Failed to call GetSecurityInfo. {0}", GetLastErrorString());
            return false;
        }

        // Create SID for Everyone and AppPackage

        IntPtr pEveryoneSid = IntPtr.Zero;
        IntPtr pAppPackageSid = IntPtr.Zero;
        uint realsize = 10;
        bool status = false;

        // Getting the correct size and allocating memory
        CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, IntPtr.Zero, ref realsize);
        pEveryoneSid = Marshal.AllocCoTaskMem(Convert.ToInt32(realsize));

        status = CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, pEveryoneSid, ref realsize);
        if (!status)
        {
            Console.WriteLine("[-] Failed to call CreateWellKnownSid. Error String: {0}, Error Code: {1}, realsize: {2}, status: {3}", GetLastErrorString(), GetLastError(), realsize, status);
            Marshal.FreeCoTaskMem(pEveryoneSid);
            return false;
        }

        // DEBUG
        // Just to check that weve got the right sid
        //bool ok = ConvertSidToStringSid(pEveryoneSid, out ptrSid);
        //Console.WriteLine("The SID is: {0:x}", Marshal.PtrToStringAuto(ptrSid));


        realsize = 10;
        status = false;
        // Getting the correct size and allocating memory
        CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinBuiltinAnyPackageSid, IntPtr.Zero, IntPtr.Zero, ref realsize);
        pAppPackageSid = Marshal.AllocCoTaskMem(Convert.ToInt32(realsize));

        status = CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinBuiltinAnyPackageSid, IntPtr.Zero, pAppPackageSid, ref realsize);
        if (!status)
        {
            Console.WriteLine("[-] Failed to call CreateWellKnownSid. Error String: {0}, Error Code: {1}, realsize: {2}, status: {3}", GetLastErrorString(), GetLastError(), realsize, status);
            Marshal.FreeCoTaskMem(pAppPackageSid);
            return false;
        }
        // Just to check that weve got the right sid
        //bool ok = ConvertSidToStringSid(pEveryoneSid, out ptrSid);
        //Console.WriteLine("The SID is: {0:x}", Marshal.PtrToStringAuto(ptrSid));




        #region WorkStation DACL
        // START Trustee and Explicit Access for Workstation DACL
        TRUSTEE[] pTrusteeWorkStation = new TRUSTEE[2];
        EXPLICIT_ACCESS[] pExplicitAccessWorkStation = new EXPLICIT_ACCESS[2];

        pTrusteeWorkStation[0].pMultipleTrustee = IntPtr.Zero;
        pTrusteeWorkStation[0].MultipleTrusteeOperation = 0;
        pTrusteeWorkStation[0].TrusteeForm = 0; // TRUSTEE_IS_SID;
        pTrusteeWorkStation[0].TrusteeType = 0; // TRUSTEE_IS_UNKNOWN;
        pTrusteeWorkStation[0].ptstrName = pEveryoneSid; // (LPWCH)EveryoneSid;

        pExplicitAccessWorkStation[0].grfAccessPermissions = 983935;// WRITE_DAC | WRITE_OWNER; // Not Sure
        pExplicitAccessWorkStation[0].grfAccessMode = 1;//GRANT_ACCESS;
        pExplicitAccessWorkStation[0].grfInheritance = 0;
        pExplicitAccessWorkStation[0].Trustee = pTrusteeWorkStation[0];

        pTrusteeWorkStation[1].pMultipleTrustee = IntPtr.Zero;
        pTrusteeWorkStation[1].MultipleTrusteeOperation = 0;
        pTrusteeWorkStation[1].TrusteeForm = 0;
        pTrusteeWorkStation[1].TrusteeType = 0;
        pTrusteeWorkStation[1].ptstrName = pAppPackageSid;

        pExplicitAccessWorkStation[1].grfAccessPermissions = 983935; //WRITE_DAC | WRITE_OWNER; // Not Sure
        pExplicitAccessWorkStation[1].grfAccessMode = 1;
        pExplicitAccessWorkStation[1].grfInheritance = 0;
        pExplicitAccessWorkStation[1].Trustee = pTrusteeWorkStation[1];
        #endregion WorkStation DACL


        #region Desktop DACL
        // START Trustee and Explicit Access for Workstation DACL
        TRUSTEE[] pTrusteeDesktop = new TRUSTEE[2];
        EXPLICIT_ACCESS[] pExplicitAccessDesktop = new EXPLICIT_ACCESS[2];

        pTrusteeDesktop[0].pMultipleTrustee = IntPtr.Zero;
        pTrusteeDesktop[0].MultipleTrusteeOperation = 0;
        pTrusteeDesktop[0].TrusteeForm = 0; // TRUSTEE_IS_SID;
        pTrusteeDesktop[0].TrusteeType = 0; // TRUSTEE_IS_UNKNOWN;
        pTrusteeDesktop[0].ptstrName = pEveryoneSid; // (LPWCH)EveryoneSid;

        pExplicitAccessDesktop[0].grfAccessPermissions = 983551;// WRITE_DAC | WRITE_OWNER; // Not Sure
        pExplicitAccessDesktop[0].grfAccessMode = 1;//GRANT_ACCESS;
        pExplicitAccessDesktop[0].grfInheritance = 0;
        pExplicitAccessDesktop[0].Trustee = pTrusteeDesktop[0];

        pTrusteeDesktop[1].pMultipleTrustee = IntPtr.Zero;
        pTrusteeDesktop[1].MultipleTrusteeOperation = 0;
        pTrusteeDesktop[1].TrusteeForm = 0;
        pTrusteeDesktop[1].TrusteeType = 0;
        pTrusteeDesktop[1].ptstrName = pAppPackageSid;

        pExplicitAccessDesktop[1].grfAccessPermissions = 983551; //WRITE_DAC | WRITE_OWNER; // Not Sure
        pExplicitAccessDesktop[1].grfAccessMode = 1;
        pExplicitAccessDesktop[1].grfInheritance = 0;
        pExplicitAccessDesktop[1].Trustee = pTrusteeDesktop[1];
        #endregion Desktop DACL

        int retval = 0;
        IntPtr NewDacl = IntPtr.Zero;

        switch (objName.ToLower())
        {
            case "workstation":
                //Console.WriteLine("[!] {0} case", objName);
                SetEntriesInAcl(2, pExplicitAccessWorkStation, ppDacl, out NewDacl);
                break;
            case "desktop":
                //Console.WriteLine("[!] {0} case", objName);
                SetEntriesInAcl(2, pExplicitAccessDesktop, ppDacl, out NewDacl);
                break;
            default:
                Console.WriteLine("[!] Hit default switch case");
                return false;
        }

        if (retval != 0)
        {
            Console.WriteLine("[-] Failed to call SetEntriesInAcl on {2}. Error Code: {0} ({1})", GetLastError(), GetLastErrorString(), objName);
        }
        Console.WriteLine("[+] SetEntriesInAcl for {0} Succeeded.", objName);


        if (NewDacl == IntPtr.Zero)
        {
            Console.WriteLine("[-] NewDacl Handle is zero. {0}", GetLastErrorString());
            Marshal.FreeCoTaskMem(pEveryoneSid);
            Marshal.FreeCoTaskMem(pAppPackageSid);
            return false;
        }


        uint success = SetSecurityInfo(hObject, SE_OBJECT_TYPE.SE_WINDOW_OBJECT, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, NewDacl, IntPtr.Zero);
        if (success != 0)
        {
            Console.WriteLine("[-] Failed to call SetSecurityInfo on WorkStation. {0}", GetLastErrorString());
            return false;
        }

        Marshal.FreeCoTaskMem(pEveryoneSid);
        Marshal.FreeCoTaskMem(pAppPackageSid);
        LocalFree(ppSecurityDescriptor);
        return true;
    }

    internal bool ListAcesFromDacl()
    {
        throw new NotImplementedException();
    }

}
