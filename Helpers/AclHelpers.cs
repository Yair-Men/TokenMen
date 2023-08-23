using System.Text;

namespace TokenMen.Acls;

internal static class AclHelpers
{



    internal static bool DisplayAcls()
    {
        SECURITY_INFORMATION secInfo = SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION |
            SECURITY_INFORMATION.SACL_SECURITY_INFORMATION | SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;

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

        //PrintAccountFromSid(ppSidOwner);
        //PrintAccountFromSid(ppSidGroup);
        PrintSecurityStringFromRawSD(ppSecurityDescriptor, ObjectTypeName.WorkStation);

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

    internal static void PrintSecurityStringFromRawSD(IntPtr pSecurityDescriptor, ObjectTypeName objectType)
    {
        SECURITY_INFORMATION secInfo = SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION |
            SECURITY_INFORMATION.SACL_SECURITY_INFORMATION | SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;

    bool ok = ConvertSecurityDescriptorToStringSecurityDescriptorA(pSecurityDescriptor, 1, secInfo, out string SecurityDescriptor, out _);
        if (ok)
            Console.WriteLine("[!] SecurityDescriptor for {0}:\n{1}", objectType, SecurityDescriptor);
        else
            Console.WriteLine("[-] ConvertSD Failed. (Error: {0})", GetLastErrorString());
    }

}
