using System;
using System.Runtime.InteropServices;
using System.Text;

public class CredentialManager
{
    private const int CRED_TYPE_GENERIC = 1;
    private const int CRED_PERSIST_LOCAL_MACHINE = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public int Flags;
        public int Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] uint flags);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("Advapi32.dll", SetLastError = true)]
    private static extern bool CredFree([In] IntPtr cred);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredDelete(string target, int type, int flags);

    public static bool AddCredential(string target, string username, string password)
    {
        var byteArray = Encoding.Unicode.GetBytes(password);
        if (byteArray.Length > 512)
        {
            throw new ArgumentOutOfRangeException("password", "The password has exceeded 512 bytes.");
        }

        var credential = new CREDENTIAL
        {
            TargetName = Marshal.StringToCoTaskMemUni(target),
            UserName = Marshal.StringToCoTaskMemUni(username),
            CredentialBlob = Marshal.StringToCoTaskMemUni(password),
            CredentialBlobSize = byteArray.Length,
            Type = CRED_TYPE_GENERIC,
            Persist = CRED_PERSIST_LOCAL_MACHINE
        };

        var result = CredWrite(ref credential, 0);

        Marshal.FreeCoTaskMem(credential.TargetName);
        Marshal.FreeCoTaskMem(credential.UserName);
        Marshal.FreeCoTaskMem(credential.CredentialBlob);

        if (!result)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        return result;
    }

    public static (string username, string password)? ReadCredential(string target)
    {
        var read = CredRead(target, CRED_TYPE_GENERIC, 0, out var credentialPtr);
        if (!read)
        {
            return null;
        }

        try
        {
            var credential = Marshal.PtrToStructure<CREDENTIAL>(credentialPtr);
            var username = Marshal.PtrToStringUni(credential.UserName);
            var password = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);
            return (username, password);
        }
        finally
        {
            CredFree(credentialPtr);
        }
    }

    public static bool DeleteCredential(string target)
    {
        var result = CredDelete(target, CRED_TYPE_GENERIC, 0);
        if (!result)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        return result;
    }

    public static bool ValidateCredential(string target, string username, string password)
    {
        var credential = ReadCredential(target);
        return credential.HasValue && credential.Value.username == username && credential.Value.password == password;
    }
}
