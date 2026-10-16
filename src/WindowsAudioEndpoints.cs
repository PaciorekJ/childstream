using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

internal sealed class ChildAudioEndpointInventory
{
    internal int SessionId;
    internal bool Complete;
    internal string DefaultRenderId;
    internal readonly HashSet<string> ActiveRenderIds = new HashSet<string>(StringComparer.Ordinal);
    internal readonly Dictionary<string, string> FriendlyNames = new Dictionary<string, string>(StringComparer.Ordinal);
}

// Read-only Core Audio endpoint enumeration. Run in the verified child process;
// endpoint presence alone does not prove Sunshine loopback or audio isolation.
internal static class WindowsAudioEndpoints
{
    [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
    private class MMDeviceEnumeratorClass { }

    [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceEnumerator
    {
        void EnumAudioEndpoints(int dataFlow, uint stateMask, out IMMDeviceCollection devices);
        void GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice device);
    }

    [ComImport, Guid("0BD7A1BE-7A1A-44DB-8397-CC5392387B5E"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceCollection
    {
        void GetCount(out uint count);
        void Item(uint index, out IMMDevice device);
    }

    [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDevice
    {
        void Activate(ref Guid iid, uint context, IntPtr parameters, out IntPtr result);
        void OpenPropertyStore(uint access, out IPropertyStore properties);
        void GetId(out IntPtr id);
        void GetState(out uint state);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PropertyKey { internal Guid Format; internal uint Id; }

    [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPropertyStore
    {
        void GetCount(out uint count);
        void GetAt(uint index, out PropertyKey key);
        void GetValue(ref PropertyKey key, IntPtr value);
        void SetValue(ref PropertyKey key, IntPtr value);
        void Commit();
    }

    [DllImport("ole32.dll")]
    private static extern int PropVariantClear(IntPtr value);

    private static string TryFriendlyName(IMMDevice device)
    {
        IPropertyStore store = null;
        IntPtr value = IntPtr.Zero;
        try
        {
            device.OpenPropertyStore(0, out store); // STGM_READ, no preference write.
            value = Marshal.AllocCoTaskMem(IntPtr.Size == 8 ? 24 : 16);
            for (int offset = 0; offset < (IntPtr.Size == 8 ? 24 : 16); offset += 4)
                Marshal.WriteInt32(value, offset, 0);
            var key = new PropertyKey { Format = new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), Id = 14 };
            store.GetValue(ref key, value);
            if (Marshal.ReadInt16(value) != 31) return null; // VT_LPWSTR
            string name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(value, 8));
            return String.IsNullOrWhiteSpace(name) || name.Length > 128 ||
                name.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0 ? null : name;
        }
        catch { return null; } // The stable endpoint ID remains authoritative.
        finally
        {
            if (value != IntPtr.Zero) { PropVariantClear(value); Marshal.FreeCoTaskMem(value); }
            if (store != null) Marshal.ReleaseComObject(store);
        }
    }

    internal static ChildAudioEndpointInventory ReadActiveRender(int expectedChildSessionId)
    {
        var result = new ChildAudioEndpointInventory { SessionId = Process.GetCurrentProcess().SessionId };
        if (expectedChildSessionId <= 0 || result.SessionId != expectedChildSessionId) return result;
        IMMDeviceEnumerator enumerator = null;
        IMMDeviceCollection devices = null;
        try
        {
            enumerator = (IMMDeviceEnumerator)new MMDeviceEnumeratorClass();
            enumerator.EnumAudioEndpoints(0, 1, out devices); // eRender, DEVICE_STATE_ACTIVE
            uint count;
            devices.GetCount(out count);
            if (count > 256) throw new InvalidOperationException("Audio endpoint count is implausible.");
            for (uint i = 0; i < count; i++)
            {
                IMMDevice device = null;
                IntPtr raw = IntPtr.Zero;
                try
                {
                    devices.Item(i, out device);
                    uint state;
                    device.GetState(out state);
                    if (state != 1) throw new InvalidOperationException("Audio endpoint changed state during enumeration.");
                    device.GetId(out raw);
                    string id = Marshal.PtrToStringUni(raw);
                    if (String.IsNullOrEmpty(id) || !result.ActiveRenderIds.Add(id))
                        throw new InvalidOperationException("Audio endpoint identity is missing or duplicated.");
                    string friendly = TryFriendlyName(device);
                    if (friendly != null) result.FriendlyNames[id] = friendly;
                }
                finally
                {
                    if (raw != IntPtr.Zero) Marshal.FreeCoTaskMem(raw);
                    if (device != null) Marshal.ReleaseComObject(device);
                }
            }
            IMMDevice defaultDevice = null;
            IntPtr defaultRaw = IntPtr.Zero;
            try
            {
                enumerator.GetDefaultAudioEndpoint(0, 1, out defaultDevice); // eRender, eMultimedia
                defaultDevice.GetId(out defaultRaw);
                result.DefaultRenderId = Marshal.PtrToStringUni(defaultRaw);
                if (String.IsNullOrEmpty(result.DefaultRenderId) ||
                    !result.ActiveRenderIds.Contains(result.DefaultRenderId))
                    throw new InvalidOperationException("Child default render endpoint is absent or inactive.");
            }
            finally
            {
                if (defaultRaw != IntPtr.Zero) Marshal.FreeCoTaskMem(defaultRaw);
                if (defaultDevice != null) Marshal.ReleaseComObject(defaultDevice);
            }
            result.Complete = true;
        }
        catch { result.ActiveRenderIds.Clear(); result.FriendlyNames.Clear(); result.DefaultRenderId = null; result.Complete = false; }
        finally
        {
            if (devices != null) Marshal.ReleaseComObject(devices);
            if (enumerator != null) Marshal.ReleaseComObject(enumerator);
        }
        return result;
    }
}
