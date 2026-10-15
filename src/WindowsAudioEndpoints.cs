using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

internal sealed class ChildAudioEndpointInventory
{
    internal int SessionId;
    internal bool Complete;
    internal readonly HashSet<string> ActiveRenderIds = new HashSet<string>(StringComparer.Ordinal);
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
        void OpenPropertyStore(uint access, out IntPtr properties);
        void GetId(out IntPtr id);
        void GetState(out uint state);
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
                }
                finally
                {
                    if (raw != IntPtr.Zero) Marshal.FreeCoTaskMem(raw);
                    if (device != null) Marshal.ReleaseComObject(device);
                }
            }
            result.Complete = true;
        }
        catch { result.ActiveRenderIds.Clear(); result.Complete = false; }
        finally
        {
            if (devices != null) Marshal.ReleaseComObject(devices);
            if (enumerator != null) Marshal.ReleaseComObject(enumerator);
        }
        return result;
    }
}
