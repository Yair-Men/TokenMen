
using System.Text;

namespace TokenMen;

internal enum ObjectType
{
    WorkStation,
    Desktop
};

internal class Acl
{
    private static readonly uint WRITE_DAC = 0x00040000;
    private static readonly uint READ_CONTROL = 0x00020000;
    private static readonly uint DESKTOP_READOBJECTS = 0x0001;
    private static readonly uint DESKTOP_WRITEOBJECTS = 0x0080;

    private static readonly SECURITY_INFORMATION secInfo = SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION |
            SECURITY_INFORMATION.SACL_SECURITY_INFORMATION | SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;

    

    internal static bool DisplayAcls() 
    {
        // Enable SeSecurityPrivilege
        if (!Utils.PrivilegeEnabler(new string[] { SE_SECURITY_NAME }))
            return false;

        #region WorkStation
        IntPtr hWinsta = OpenWindowStation("WinSta0", false, WRITE_DAC | READ_CONTROL);
        if (hWinsta == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to get handle to Windows Station. (Error: {0})", GetLastErrorString());
            return false;
        }
        Console.WriteLine("[+] OpenWindowStation Success");


        uint dwErrCode = GetSecurityInfo(hWinsta, SE_OBJECT_TYPE.SE_FILE_OBJECT, secInfo, out IntPtr ppSidOwner,
            out IntPtr ppSidGroup, out IntPtr ppDacl, out IntPtr ppSacl, out IntPtr ppSecurityDescriptor);
        if (dwErrCode != 0)
        {
            Console.WriteLine("[-] Failed to call GetSecurityInfo. {0}", GetLastErrorString());
            return false;
        }
        Console.WriteLine("[+] GetSecurityInfo Success");

        PrintAccountFromSid(ppSidOwner);
        PrintAccountFromSid(ppSidGroup);
        PrintSecurityStringFromRawSD(ppSecurityDescriptor, ObjectType.WorkStation);

        /// Parse SecurityDescriptor to get ACEs and TRUSTEE
        uint ret = LookupSecurityDescriptorPartsA(out IntPtr pTrusteeOwner, out IntPtr pTrusteeGroup, out uint dwDaclEntries,
            out IntPtr ppListOfDaclEa, out uint dwSaclEntries, out IntPtr ppListOfSaclEa, ppSecurityDescriptor);
        if (ret != 0)
        {
            Console.WriteLine("[-] Parsing SecurityDescriptor Failed. (Error: {0})", GetLastErrorString());
            return false;
        }
        Console.WriteLine("[+] Parsing SecurityDescriptor Succeeded");


#if DEBUG
        var trusteeOwner = Marshal.PtrToStructure<TRUSTEE_A>(pTrusteeOwner);
        Console.WriteLine("The trusteeOwner is: {0}", trusteeOwner.strName);

        var trusteeGroup = Marshal.PtrToStructure<TRUSTEE_A>(pTrusteeGroup);
        Console.WriteLine("The trusteeGroup is: {0}", trusteeGroup.strName);
#endif

        /// Create a new EXPLICIT_ACESS_A array to push all the Aces by incrementing the pointer (ppListOfDaclEa) up one struct size
        /// Up until the number of entries in dwDaclEntries
        var eaDaclList = new EXPLICIT_ACCESS_A[dwDaclEntries];
        int jump = Marshal.SizeOf<EXPLICIT_ACCESS_A>();
        uint i = 0;
        while (i < dwDaclEntries)
        {
            eaDaclList[i++] = Marshal.PtrToStructure<EXPLICIT_ACCESS_A>(ppListOfDaclEa);
            ppListOfDaclEa += jump;
        }

        Console.WriteLine("Finished");
        #endregion


        #region Desktop
        //IntPtr hDesktop = OpenDesktopA("Default", 0, false, WRITE_DAC | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS);
        //if (hDesktop == IntPtr.Zero)
        //{
        //    Console.WriteLine("[-] Failed to get handle to Desktop. (Error: {0})", GetLastErrorString());
        //    CloseHandle(hWinsta);
        //    return false;
        //}
        #endregion

        return true;
    }

    private static void PrintSecurityStringFromRawSD(IntPtr pSecurityDescriptor, ObjectType objectType)
    {
        bool ok = ConvertSecurityDescriptorToStringSecurityDescriptorA(pSecurityDescriptor, 1, secInfo, out string SecurityDescriptor, out _);
        if (ok)
            Console.WriteLine("[!] SecurityDescriptor for {0}:\n{1}", objectType, SecurityDescriptor);
        else
            Console.WriteLine("[-] ConvertSD Failed. (Error: {0})", GetLastErrorString());
    }

    private static void PrintAccountFromSid(IntPtr pSID)
    {
        bool ok = ConvertSidToStringSid(pSID, out IntPtr ptrSid);
        if (ok)
            Console.WriteLine("[!] SID: {0}", Marshal.PtrToStringAuto(ptrSid));
        else
            Console.WriteLine("[-] ConvertSidToStringSid Failed. (Error: {0})", GetLastErrorString());

        uint dwAcctName = 1;
        uint dwDomainName = 1;
        StringBuilder AcctName = new();
        StringBuilder DomainName = new();

        // First time to get and adjust the size
        LookupAccountSidA(null, pSID, AcctName, ref dwAcctName, DomainName, ref dwDomainName, out _);
        AcctName.EnsureCapacity((int)dwAcctName);
        DomainName.EnsureCapacity((int)dwDomainName);

        ok = LookupAccountSidA(null, pSID, AcctName, ref dwAcctName, DomainName, ref dwDomainName, out SID_NAME_USE eUse);
        if (ok)
            Console.WriteLine("SID Type: {0}\nSID Owner: {1}\\{2}", eUse, DomainName, AcctName);
        else
            Console.WriteLine("[-] LookupAccountSidA Failed. (Error: {0})", GetLastErrorString());
        

        

    }

    internal static bool ChangeDesktopACL()
    {
        // Enable SeSecurityPrivilege
        if (!Utils.PrivilegeEnabler(new string[] { SE_SECURITY_NAME }))
            return false;

        

        IntPtr hWinsta = OpenWindowStation("WinSta0", false, WRITE_DAC | READ_CONTROL);

        if (hWinsta == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to get handle to Windows Station. (Error: {0})", GetLastErrorString());
            return false;
        }

        if (!ChangeACL(hWinsta, ObjectType.WorkStation))
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

        if (!ChangeACL(hDesktop, ObjectType.Desktop))
        {
            Console.WriteLine("[-] Failed to set Dacl on Desktop. (Error: {0})", GetLastErrorString());
            CloseHandle(hDesktop);
            return false;
        }

        CloseHandle(hDesktop);
        CloseHandle(hWinsta);

        return true;
    }

    private static bool ChangeACL(IntPtr hObject, ObjectType objName)
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
            Console.WriteLine("[-] Failed to create SID. (Error: {0})",GetLastErrorString());
            Marshal.FreeCoTaskMem(pEveryoneSid);
            return false;
        }


        realsize = 10;
        // Getting the correct size and allocating memory
        CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinBuiltinAnyPackageSid, IntPtr.Zero, IntPtr.Zero, ref realsize);
        pAppPackageSid = Marshal.AllocCoTaskMem((int)realsize);

        status = CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinBuiltinAnyPackageSid, IntPtr.Zero, pAppPackageSid, ref realsize);
        if (!status)
        {
            Console.WriteLine("[-] Failed to create SID. (Error: {0})",GetLastErrorString());
            Marshal.FreeCoTaskMem(pAppPackageSid);
            return false;
        }


        // EnumDesktops|ReadAttributes|AccessClipboard|CreateDesktop|WriteAttributes|AccessGlobalAtoms|ExitWindows|Enumerate|ReadScreen|Delete|ReadControl|WriteDac|WriteOwner
        uint accessPermissions = 983_935;

        #region WorkStation DACL
        // START Trustee and Explicit Access for Workstation DACL
        var pTrusteeWorkStation = new TRUSTEE[2];
        var pListOfExplicitEntriesWorkStation = new EXPLICIT_ACCESS[2];

        //IntPtr pEveryOneSid = Marshal.AllocHGlobal(1);
        //Marshal.WriteInt32(pEveryOneSid, WellKnownSidType.WorldSid);

        pTrusteeWorkStation[0].pMultipleTrustee = IntPtr.Zero;
        pTrusteeWorkStation[0].MultipleTrusteeOperation = MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE;
        pTrusteeWorkStation[0].TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID;
        pTrusteeWorkStation[0].TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_UNKNOWN;
        pTrusteeWorkStation[0].ptstrName = pEveryoneSid; // (LPWCH)EveryoneSid;

        pListOfExplicitEntriesWorkStation[0].grfAccessPermissions = accessPermissions;
        pListOfExplicitEntriesWorkStation[0].grfAccessMode = ACCESS_MODE.GRANT_ACCESS;
        pListOfExplicitEntriesWorkStation[0].grfInheritance = 0;
        pListOfExplicitEntriesWorkStation[0].Trustee = pTrusteeWorkStation[0];
        
        pTrusteeWorkStation[1].pMultipleTrustee = IntPtr.Zero;
        pTrusteeWorkStation[1].MultipleTrusteeOperation = MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE;
        pTrusteeWorkStation[1].TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID;
        pTrusteeWorkStation[1].TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_UNKNOWN;
        pTrusteeWorkStation[1].ptstrName = pAppPackageSid;

        pListOfExplicitEntriesWorkStation[1].grfAccessPermissions = accessPermissions;
        pListOfExplicitEntriesWorkStation[1].grfAccessMode = ACCESS_MODE.GRANT_ACCESS;
        pListOfExplicitEntriesWorkStation[1].grfInheritance = 0;
        pListOfExplicitEntriesWorkStation[1].Trustee = pTrusteeWorkStation[1];
        #endregion WorkStation DACL


        #region Desktop DACL
        // START Trustee and Explicit Access for Workstation DACL
        var pTrusteeDesktop = new TRUSTEE[2];
        var pListOfExplicitEntriesDesktop = new EXPLICIT_ACCESS[2];

        pTrusteeDesktop[0].pMultipleTrustee = IntPtr.Zero;
        pTrusteeDesktop[0].MultipleTrusteeOperation = MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE;
        pTrusteeDesktop[0].TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID;
        pTrusteeDesktop[0].TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_UNKNOWN;
        pTrusteeDesktop[0].ptstrName = pEveryoneSid; // (LPWCH)EveryoneSid;

        pListOfExplicitEntriesDesktop[0].grfAccessPermissions = accessPermissions;
        pListOfExplicitEntriesDesktop[0].grfAccessMode = ACCESS_MODE.GRANT_ACCESS;
        pListOfExplicitEntriesDesktop[0].grfInheritance = 0;
        pListOfExplicitEntriesDesktop[0].Trustee = pTrusteeDesktop[0];

        pTrusteeDesktop[1].pMultipleTrustee = IntPtr.Zero;
        pTrusteeDesktop[1].MultipleTrusteeOperation = MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE;
        pTrusteeDesktop[1].TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID;
        pTrusteeDesktop[1].TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_UNKNOWN;
        pTrusteeDesktop[1].ptstrName = pAppPackageSid;

        pListOfExplicitEntriesDesktop[1].grfAccessPermissions = accessPermissions;
        pListOfExplicitEntriesDesktop[1].grfAccessMode = ACCESS_MODE.GRANT_ACCESS;
        pListOfExplicitEntriesDesktop[1].grfInheritance = 0;
        pListOfExplicitEntriesDesktop[1].Trustee = pTrusteeDesktop[1];
        #endregion Desktop DACL

        int retval = 0;
        IntPtr NewDacl = IntPtr.Zero;
        
        switch (objName)
        {
            case ObjectType.WorkStation:
                SetEntriesInAcl(2, pListOfExplicitEntriesWorkStation, ppDacl, out NewDacl);
                break;
            case ObjectType.Desktop:
                SetEntriesInAcl(2, pListOfExplicitEntriesDesktop, ppDacl, out NewDacl);
                break;
            default:
                Console.WriteLine("[-] Unknown Object Type");
                return false;
        }

        if (retval != 0)
        {
            Console.WriteLine("[-] Failed to call SetEntriesInAcl on {0}. Error Code: {0} ({1})", objName, GetLastError(), GetLastErrorString());
        }
        Console.WriteLine("[+] SetEntriesInAcl for {0} Succeeded.", objName);


        if (NewDacl == IntPtr.Zero)
        {
            Console.WriteLine("[-] NewDacl Handle is zero. (Error: {0})", GetLastErrorString());
            Marshal.FreeCoTaskMem(pEveryoneSid);
            Marshal.FreeCoTaskMem(pAppPackageSid);
            return false;
        }


        uint success = SetSecurityInfo(hObject, SE_OBJECT_TYPE.SE_WINDOW_OBJECT, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, NewDacl, IntPtr.Zero);
        if (success != 0)
        {
            Console.WriteLine("[-] Failed to apply new ACL. (Error: {0})", GetLastErrorString());
            return false;
        }

        Marshal.FreeCoTaskMem(pEveryoneSid);
        Marshal.FreeCoTaskMem(pAppPackageSid);
        LocalFree(ppSecurityDescriptor);
        return true;
    }

    //internal bool ListAcesFromDacl()
    //{
    //    throw new NotImplementedException();
    //}

}
