using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal sealed class ProcessTokenObservation
{
    internal string Sid;
    internal RuntimeTokenStatus Elevation;
}

internal static class WindowsProcessToken
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, out int value, int length, out int returned);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    internal static ProcessTokenObservation Read(int pid)
    {
        if (pid <= 0) throw new ArgumentOutOfRangeException("pid");
        IntPtr process = OpenProcess(0x1000, false, (uint)pid); // PROCESS_QUERY_LIMITED_INFORMATION
        if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Process token cannot be verified.");
        IntPtr token = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(process, 0x0008, out token)) // TOKEN_QUERY
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Process token cannot be opened.");
            int elevated, returned;
            if (!GetTokenInformation(token, 20, out elevated, sizeof(int), out returned) || returned != sizeof(int))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Process elevation cannot be verified.");
            using (var identity = new WindowsIdentity(token))
            {
                if (identity.User == null) throw new InvalidOperationException("Process SID cannot be verified.");
                return new ProcessTokenObservation { Sid = identity.User.Value,
                    Elevation = elevated == 0 ? RuntimeTokenStatus.Limited : RuntimeTokenStatus.Elevated };
            }
        }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
            CloseHandle(process);
        }
    }
}
