using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

internal static class ManifestTests
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string path, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr FindResource(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LockResource(IntPtr resource);
    private static string Embedded(string path)
    {
        IntPtr module = LoadLibraryEx(path, IntPtr.Zero, 0x20);
        if (module == IntPtr.Zero) throw new InvalidOperationException("Executable cannot be opened as PE data: " + path);
        try
        {
            IntPtr resource = FindResource(module, new IntPtr(1), new IntPtr(24));
            if (resource == IntPtr.Zero) throw new InvalidDataException("Executable has no RT_MANIFEST: " + path);
            int length = SizeofResource(module, resource);
            if (length <= 0 || length > 65536) throw new InvalidDataException("Manifest size is invalid.");
            IntPtr data = LockResource(LoadResource(module, resource));
            if (data == IntPtr.Zero) throw new InvalidDataException("Manifest cannot be read.");
            byte[] bytes = new byte[length]; Marshal.Copy(data, bytes, 0, length);
            return Encoding.UTF8.GetString(bytes);
        }
        finally { FreeLibrary(module); }
    }
    public static int Main(string[] args)
    {
        string app = Embedded(args[0]), helper = Embedded(args[1]);
        if (!app.Contains("level=\"asInvoker\"") || !app.Contains("uiAccess=\"false\"") ||
            !helper.Contains("level=\"requireAdministrator\"") || !helper.Contains("uiAccess=\"false\""))
            throw new Exception("Built executable elevation manifests do not match the privilege boundary.");
        Console.WriteLine("Embedded PE manifests verified: app asInvoker; helper requireAdministrator; uiAccess false.");
        return 0;
    }
}
