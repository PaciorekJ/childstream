using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

// Read-only Core Audio observation in the child agent. Only PID, active state
// and endpoint identity are read; no other application's process is opened.
internal static class WindowsGameAudioSessions
{
    private const int NoSingleProcess = 0x0889000d; // AUDCLNT_S_NO_SINGLE_PROCESS

    [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
    private class MMDeviceEnumeratorClass { }
    [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceEnumerator
    {
        void EnumAudioEndpoints(int flow, uint state, out IMMDeviceCollection devices);
        void GetDefaultAudioEndpoint(int flow, int role, out IMMDevice device);
        void GetDevice([MarshalAs(UnmanagedType.LPWStr)] string id, out IMMDevice device);
    }
    [ComImport, Guid("0BD7A1BE-7A1A-44DB-8397-CC5392387B5E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceCollection
    {
        void GetCount(out uint count);
        void Item(uint index, out IMMDevice device);
    }
    [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDevice
    {
        void Activate(ref Guid iid, uint context, IntPtr parameters, out IntPtr result);
        void OpenPropertyStore(uint access, out IntPtr properties);
        void GetId(out IntPtr id);
        void GetState(out uint state);
    }
    [ComImport, Guid("77AA99A0-1BD6-484F-8BC7-2C654C9A9B6F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioSessionManager2
    {
        void GetAudioSessionControl(ref Guid session, uint flags, out IntPtr control);
        void GetSimpleAudioVolume(ref Guid session, uint flags, out IntPtr volume);
        void GetSessionEnumerator(out IAudioSessionEnumerator enumerator);
    }
    [ComImport, Guid("E2F5BB11-0570-40CA-ACDD-3AA01277DEE8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioSessionEnumerator
    {
        void GetCount(out int count);
        void GetSession(int index, out IAudioSessionControl control);
    }
    [ComImport, Guid("F4B1A599-7266-4319-A8CA-E70ACB11E8CD"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioSessionControl
    {
        void GetState(out int state);
        void GetDisplayName(out IntPtr name);
        void SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] string name, ref Guid context);
        void GetIconPath(out IntPtr path);
        void SetIconPath([MarshalAs(UnmanagedType.LPWStr)] string path, ref Guid context);
        void GetGroupingParam(out Guid grouping);
        void SetGroupingParam(ref Guid grouping, ref Guid context);
        void RegisterAudioSessionNotification(IntPtr events);
        void UnregisterAudioSessionNotification(IntPtr events);
    }
    [ComImport, Guid("BFB7FF88-7239-4FC9-8FA2-07C950BE9C6D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioSessionControl2
    {
        void GetState(out int state);
        void GetDisplayName(out IntPtr name);
        void SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] string name, ref Guid context);
        void GetIconPath(out IntPtr path);
        void SetIconPath([MarshalAs(UnmanagedType.LPWStr)] string path, ref Guid context);
        void GetGroupingParam(out Guid grouping);
        void SetGroupingParam(ref Guid grouping, ref Guid context);
        void RegisterAudioSessionNotification(IntPtr events);
        void UnregisterAudioSessionNotification(IntPtr events);
        void GetSessionIdentifier(out IntPtr id);
        void GetSessionInstanceIdentifier(out IntPtr id);
        [PreserveSig] int GetProcessId(out uint pid);
    }

    internal static GameAudioSessionSnapshot Read(ChildSessionIdentity child, ChildAudioEndpointInventory endpoints,
        int exactGamePid)
    {
        var result = new GameAudioSessionSnapshot();
        if (exactGamePid <= 0 || Process.GetCurrentProcess().SessionId != (int)child.SessionId || endpoints == null ||
            !endpoints.Complete || endpoints.SessionId != (int)child.SessionId ||
            endpoints.ActiveRenderIds.Count > 64) return result;
        IMMDeviceEnumerator devices = null;
        try
        {
            devices = (IMMDeviceEnumerator)new MMDeviceEnumeratorClass();
            var ordered = new List<string>(endpoints.ActiveRenderIds);
            ordered.Sort(StringComparer.Ordinal);
            foreach (string id in ordered) ReadEndpoint(devices, id, exactGamePid, result);
            result.Complete = true;
        }
        catch { result.Complete = false; result.Sessions.Clear(); }
        finally { if (devices != null) Marshal.ReleaseComObject(devices); }
        return result;
    }

    private static void ReadEndpoint(IMMDeviceEnumerator devices, string id, int exactGamePid,
        GameAudioSessionSnapshot result)
    {
        IMMDevice device = null;
        IAudioSessionManager2 manager = null;
        IAudioSessionEnumerator sessions = null;
        IntPtr raw = IntPtr.Zero;
        try
        {
            devices.GetDevice(id, out device);
            uint state; device.GetState(out state);
            if (state != 1) throw new InvalidOperationException("Audio endpoint changed state.");
            Guid iid = typeof(IAudioSessionManager2).GUID;
            device.Activate(ref iid, 23, IntPtr.Zero, out raw); // CLSCTX_ALL
            manager = (IAudioSessionManager2)Marshal.GetObjectForIUnknown(raw);
            manager.GetSessionEnumerator(out sessions);
            int count; sessions.GetCount(out count);
            if (count < 0 || count > 4096) throw new InvalidOperationException("Audio session count is implausible.");
            for (int i = 0; i < count; i++)
            {
                IAudioSessionControl baseControl = null;
                try
                {
                    sessions.GetSession(i, out baseControl);
                    var control = (IAudioSessionControl2)baseControl;
                    int active; control.GetState(out active);
                    uint pid; int hr = control.GetProcessId(out pid);
                    if (hr != 0 && hr != NoSingleProcess) Marshal.ThrowExceptionForHR(hr);
                    if (pid > Int32.MaxValue) throw new InvalidOperationException("Audio PID is invalid.");
                    // Do not retain unrelated process identifiers or metadata.
                    if (hr == NoSingleProcess || pid == (uint)exactGamePid)
                        result.Sessions.Add(new GameAudioSession { EndpointId = id,
                            ProcessId = hr == NoSingleProcess ? 0 : (int)pid,
                            Active = active == 1, MultiProcess = hr == NoSingleProcess });
                }
                finally { if (baseControl != null) Marshal.ReleaseComObject(baseControl); }
            }
        }
        finally
        {
            if (sessions != null) Marshal.ReleaseComObject(sessions);
            if (manager != null) Marshal.ReleaseComObject(manager);
            if (raw != IntPtr.Zero) Marshal.Release(raw);
            if (device != null) Marshal.ReleaseComObject(device);
        }
    }
}
