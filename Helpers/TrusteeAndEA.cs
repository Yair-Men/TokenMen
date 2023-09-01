namespace TokenMen.Helpers;


internal static class TrusteeAndEA
{
    /// <summary>
    /// Create new TRUSTEE struct to use in EXPLICIT_ACESS.
    /// If trusteeForm is TRUSTEE_IS_NAME, then ptstrName must be a pointer to string conatins the user name
    /// If trusteeForm is TRUSTEE_IS_SID, then ptstrName must be a pointer to the user's SID
    /// </summary>
    /// <param name="trusteeForm">TRUSTEE_IS_SID or TRUSTEE_IS_NAME</param>
    /// <param name="ptstrName">If trusteeForm is SID - pointer to SID, if trusteeForm is NAME - Pointer to string user's name</param>
    /// <returns>TRUSTEE</returns>
    internal static TRUSTEE CreateTrustee(TRUSTEE_FORM trusteeForm, IntPtr ptstrName)
    {
     

        TRUSTEE trustee = new()
        {
            pMultipleTrustee = IntPtr.Zero,
            MultipleTrusteeOperation = MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE,
            TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_UNKNOWN,
            TrusteeForm = trusteeForm,
            ptstrName = ptstrName
        };

        return trustee;
    }


    /// <summary>
    /// Create EXPLICIT_ACCESS Structure to Grant or revoke access for user to object (Workstation/Desktop)
    /// </summary>
    /// <param name="trustee">TRUSTEE instance</param>
    /// <param name="permissions">Permissions to apply on object</param>
    /// <param name="accessMode">Whether to Grant or revoke access</param>
    /// <returns>new EXPLICIT_ACCESS instance</returns>
    internal static EXPLICIT_ACCESS CreateEa(TRUSTEE trustee, ObjectTypePermission permissions, ACCESS_MODE accessMode)
    {
        EXPLICIT_ACCESS EA = new()
        {
            grfAccessPermissions = (uint)permissions,
            grfAccessMode = accessMode,
            grfInheritance = 0,
            Trustee = trustee
        };

        return EA;
    }

}
