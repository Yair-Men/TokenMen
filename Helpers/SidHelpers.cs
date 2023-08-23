using System.Text;

namespace TokenMen.Helpers;

internal static class SidHelpers
{

    /// <summary>
    /// Get pointer to Raw/Binary SID 
    /// </summary>
    /// <param name="hToken">Handle for Access Token</param>
    /// <returns>Pointer to user's SID or IntPtr.Zero if failed</returns>
    internal static IntPtr GetSidFromAccessToken(IntPtr hToken)
    {
        IntPtr pTokenInfo = IntPtr.Zero;

        if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, 0, out uint retLen))
        {
            if (GetLastError() != 122) // ERROR_INSUFFICIENT_BUFFER
            {
                Console.WriteLine("[-] Failed to get token information. (Error: {0})", GetLastErrorString());
                return IntPtr.Zero;
            }

            pTokenInfo = Marshal.AllocHGlobal((int)retLen);
            if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, pTokenInfo, retLen, out _))
            {
                Console.WriteLine("[-] Failed to get token information. (Error: {0})", GetLastErrorString());
                return IntPtr.Zero;
            }
        }
        Console.WriteLine("[+] Got token information");

        TOKEN_USER data = Marshal.PtrToStructure<TOKEN_USER>(pTokenInfo);

        return data.User.pSID;
    }

    internal static void PrintStringSidFromSid(IntPtr pSID)
    {
        if (ConvertSidToStringSid(pSID, out IntPtr strSid))
        {
            Console.WriteLine("[!] SID in token: {0}", Marshal.PtrToStringAuto(strSid));
        }
    }


    
    /// <summary>
    /// Create Sids For WellKnown Groups/Users
    /// </summary>
    /// <param name="sidType"> Type of Group/User</param>
    /// <returns> Pointer to the SID or IntPtr.Zero</returns>
    internal static IntPtr CreatePermissiveSid(WELL_KNOWN_SID_TYPE sidType)
    {
        //IntPtr pSid = IntPtr.Zero;
        uint realsize = 10;

        // Everyone SID
        CreateWellKnownSid(sidType, IntPtr.Zero, IntPtr.Zero, ref realsize);
        IntPtr pSid = Marshal.AllocCoTaskMem(Convert.ToInt32(realsize));

        bool status = CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinWorldSid, IntPtr.Zero, pSid, ref realsize);
        if (!status)
        {
            Console.WriteLine("[-] Failed to create SID. (Error: {0})", GetLastErrorString());
            Marshal.FreeCoTaskMem(pSid);
            return IntPtr.Zero;
        }

        return pSid;
    }
    
    internal static void PrintAccountFromSid(IntPtr pSID)
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

}
