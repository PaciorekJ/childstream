using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

// Native entry points are reachable only through explicit future live commands.
// The default kit and every CI self-test inject substitutes instead.
internal sealed class PinnedViGEmX360 : IKitTarget, IDisposable
{
    private const uint Success = 0x20000000;
    private IntPtr client, target;
    private bool attached;
    [StructLayout(LayoutKind.Sequential)] private struct XusbReport
    { public ushort Buttons; public byte LeftTrigger, RightTrigger;
      public short LeftX, LeftY, RightX, RightY; }
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern IntPtr vigem_alloc();
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern void vigem_free(IntPtr p);
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern uint vigem_connect(IntPtr p);
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern void vigem_disconnect(IntPtr p);
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern IntPtr vigem_target_x360_alloc();
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern void vigem_target_free(IntPtr p);
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern uint vigem_target_add(IntPtr c, IntPtr t);
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern uint vigem_target_remove(IntPtr c, IntPtr t);
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern uint vigem_target_get_index(IntPtr t);
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern uint vigem_target_x360_get_user_index(IntPtr c, IntPtr t, out uint slot);
    [DllImport("ViGEmClient.dll", CallingConvention = CallingConvention.Cdecl)] private static extern uint vigem_target_x360_update(IntPtr c, IntPtr t, XusbReport r);
    public bool Attached { get { return attached; } }
    public uint CreateNeutral()
    {
        if (client != IntPtr.Zero || target != IntPtr.Zero) throw new InvalidOperationException("Target already created.");
        client = vigem_alloc();
        if (client == IntPtr.Zero) throw new InvalidOperationException("ViGEm client allocation failed.");
        try
        {
            Check(vigem_connect(client), "connect");
            target = vigem_target_x360_alloc();
            if (target == IntPtr.Zero) throw new InvalidOperationException("ViGEm target allocation failed.");
            Check(vigem_target_add(client, target), "add neutral target");
            attached = true; // The driver may already expose neutral state; no feeder report was sent.
            uint serial = vigem_target_get_index(target);
            if (serial == 0 || serial > 255) throw new InvalidOperationException("ViGEm returned invalid target serial.");
            return serial;
        }
        catch { try { Remove(); } catch { } throw; }
    }
    public void Submit(ushort buttons)
    {
        if (!attached) throw new InvalidOperationException("No attached target.");
        Check(vigem_target_x360_update(client, target, new XusbReport { Buttons = buttons }), "submit test report");
    }
    internal uint UserIndex()
    {
        if (!attached) throw new InvalidOperationException("No attached target for XInput index.");
        uint slot;
        Check(vigem_target_x360_get_user_index(client, target, out slot), "read exact X360 user index");
        if (slot > 3) throw new InvalidOperationException("X360 user index outside supported XInput slots.");
        return slot;
    }
    public void Remove()
    {
        if (attached)
        {
            uint result = vigem_target_remove(client, target);
            if (result != Success) throw new InvalidOperationException("ViGEm removal failed: 0x" + result.ToString("X8"));
            attached = false;
        }
        if (target != IntPtr.Zero) { vigem_target_free(target); target = IntPtr.Zero; }
        if (client != IntPtr.Zero) { vigem_disconnect(client); vigem_free(client); client = IntPtr.Zero; }
    }
    public void Dispose() { Remove(); }
    private static void Check(uint status, string op)
    { if (status != Success) throw new InvalidOperationException("ViGEm " + op + " failed: 0x" + status.ToString("X8")); }
}

internal sealed class WindowsKitWorld : IKitWorld
{
    private const uint DigcfPresent = 2, DigcfAllClasses = 4, DigcfDeviceInterface = 16;
    private const uint SpdrpHardwareId = 1, SpdrpService = 4;
    private const uint DevpropUInt32 = 7;
    private const int ErrorNoMoreItems = 259, ErrorNotFound = 1168, ErrorInsufficientBuffer = 122;
    [StructLayout(LayoutKind.Sequential)] private struct DeviceInfo
    { public uint Size; public Guid ClassGuid; public uint DevInst; public IntPtr Reserved; }
    [StructLayout(LayoutKind.Sequential)] private struct InterfaceInfo
    { public uint Size; public Guid ClassGuid; public uint Flags; public IntPtr Reserved; }
    [StructLayout(LayoutKind.Sequential)] private struct PropKey
    { public Guid Format; public uint Pid; }
    private static readonly PropKey SessionKey = new PropKey
    { Format = new Guid("83da6326-97a6-4088-9453-a1923f573b29"), Pid = 6 };
    private static readonly Guid ViGEmInterface = new Guid("96e42b22-f5e9-42f8-b043-ed0f932f014f");
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(IntPtr cls, string enumerator, IntPtr owner, uint flags);
    [DllImport("setupapi.dll", EntryPoint = "SetupDiGetClassDevsW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupDiGetInterfaceClassDevs(ref Guid cls, string enumerator, IntPtr owner, uint flags);
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInterfaces(IntPtr set, IntPtr device, ref Guid cls, uint index, ref InterfaceInfo data);
    [DllImport("setupapi.dll", EntryPoint = "SetupDiGetDeviceInterfaceDetailW", SetLastError = true)]
    private static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr set, ref InterfaceInfo data, IntPtr detail,
        uint bytes, out uint required, ref DeviceInfo device);
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInfo(IntPtr set, uint index, ref DeviceInfo data);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiGetDeviceInstanceId(IntPtr set, ref DeviceInfo data, StringBuilder id, uint chars, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiOpenDeviceInfo(IntPtr set, string id, IntPtr window, uint flags, ref DeviceInfo data);
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiGetDeviceRegistryProperty(IntPtr set, ref DeviceInfo data, uint property,
        out uint type, byte[] buffer, uint bytes, out uint required);
    [DllImport("setupapi.dll", EntryPoint = "SetupDiGetDevicePropertyW", SetLastError = true)]
    private static extern bool SetupDiGetDeviceProperty(IntPtr set, ref DeviceInfo data, ref PropKey key,
        out uint type, byte[] buffer, uint bytes, out uint required, uint flags);
    [DllImport("setupapi.dll", EntryPoint = "SetupDiSetDevicePropertyW", SetLastError = true)]
    private static extern bool SetupDiSetDeviceProperty(IntPtr set, ref DeviceInfo data, ref PropKey key,
        uint type, byte[] buffer, uint bytes, uint flags);
    [DllImport("setupapi.dll", SetLastError = true)] private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("cfgmgr32.dll", SetLastError = true)] private static extern uint CM_Get_Parent(out uint parent, uint child, uint flags);
    [DllImport("cfgmgr32.dll", SetLastError = true)] private static extern uint CM_Get_Child(out uint child, uint parent, uint flags);
    [DllImport("cfgmgr32.dll", SetLastError = true)] private static extern uint CM_Get_Sibling(out uint sibling, uint device, uint flags);
    [DllImport("cfgmgr32.dll", EntryPoint = "CM_Get_Device_IDW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint CM_Get_Device_ID(uint device, StringBuilder id, uint chars, uint flags);
    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    private static extern bool WtsQuery(IntPtr server, uint session, int infoClass, out IntPtr data, out int bytes);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSGetChildSessionId(out uint session);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr data);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct WtsLevel1
    { public uint SessionId; public int State, Flags;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string Station;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string User;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] public string Domain;
      public long LogonTime; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct WtsInfoEx
    { public uint Level; public WtsLevel1 Data; }
    private static DeviceInfo Blank() { return new DeviceInfo { Size = (uint)Marshal.SizeOf(typeof(DeviceInfo)) }; }
    private static IntPtr Open(bool presentOnly = true)
    {
        IntPtr set = SetupDiGetClassDevs(IntPtr.Zero, null, IntPtr.Zero, DigcfAllClasses | (presentOnly ? DigcfPresent : 0));
        if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "PnP inventory unavailable");
        return set;
    }
    private static string Instance(IntPtr set, ref DeviceInfo data)
    {
        uint need; var name = new StringBuilder(512);
        if (!SetupDiGetDeviceInstanceId(set, ref data, name, (uint)name.Capacity, out need))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Device instance identity unavailable");
        return name.ToString();
    }
    private static string Parent(DeviceInfo data)
    {
        uint parent;
        uint result = CM_Get_Parent(out parent, data.DevInst, 0);
        if (result != 0) return null; // Root has no parent.
        var id = new StringBuilder(512);
        result = CM_Get_Device_ID(parent, id, (uint)id.Capacity, 0);
        if (result != 0) throw new InvalidOperationException("PnP parent identity unavailable: " + result);
        return id.ToString();
    }
    private static string[] RegistryStrings(IntPtr set, ref DeviceInfo data, uint property)
    {
        uint type, required;
        var bytes = new byte[4096];
        if (!SetupDiGetDeviceRegistryProperty(set, ref data, property, out type, bytes, (uint)bytes.Length, out required))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound) return new string[0];
            throw new Win32Exception(error, "PnP property unavailable");
        }
        if (required > bytes.Length || (required & 1) != 0 || (type != 1 && type != 7))
            throw new InvalidOperationException("PnP property has unexpected type or size.");
        return Encoding.Unicode.GetString(bytes, 0, (int)required).TrimEnd('\0').Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
    }
    public KitNode[] Nodes()
    {
        // Enumerate only present ViGEmBus interfaces, then walk their own PnP
        // subtrees. Never inventory unrelated USB or physical controllers.
        Guid cls = ViGEmInterface;
        IntPtr busSet = SetupDiGetInterfaceClassDevs(ref cls, null, IntPtr.Zero, DigcfPresent | DigcfDeviceInterface);
        if (busSet == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "ViGEmBus interface unavailable");
        IntPtr set = Open();
        try
        {
            var list = new List<KitNode>();
            uint interfaceCount = 0;
            for (uint i = 0; i < 4; i++)
            {
                var iface = new InterfaceInfo { Size = (uint)Marshal.SizeOf(typeof(InterfaceInfo)) };
                if (!SetupDiEnumDeviceInterfaces(busSet, IntPtr.Zero, ref cls, i, ref iface))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ErrorNoMoreItems) break;
                    throw new Win32Exception(error, "ViGEmBus interface enumeration incomplete");
                }
                interfaceCount++;
                uint needed;
                DeviceInfo bus = Blank();
                SetupDiGetDeviceInterfaceDetail(busSet, ref iface, IntPtr.Zero, 0, out needed, ref bus);
                if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || needed < 8 || needed > 4096)
                    throw new InvalidOperationException("ViGEmBus interface detail shape is invalid.");
                IntPtr detail = Marshal.AllocHGlobal((int)needed);
                try
                {
                    Marshal.WriteInt32(detail, IntPtr.Size == 8 ? 8 : 6);
                    bus = Blank();
                    if (!SetupDiGetDeviceInterfaceDetail(busSet, ref iface, detail, needed, out needed, ref bus))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "ViGEmBus identity unavailable");
                    var queue = new Queue<uint>(); queue.Enqueue(bus.DevInst);
                    while (queue.Count > 0)
                    {
                        if (list.Count >= 64) throw new InvalidOperationException("ViGEmBus subtree exceeds bounded limit.");
                        uint devinst = queue.Dequeue();
                        var id = new StringBuilder(512);
                        if (CM_Get_Device_ID(devinst, id, (uint)id.Capacity, 0) != 0)
                            throw new InvalidOperationException("ViGEmBus subtree identity unavailable.");
                        DeviceInfo d = Blank();
                        if (!SetupDiOpenDeviceInfo(set, id.ToString(), IntPtr.Zero, 0, ref d))
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "ViGEmBus subtree node unavailable");
                        string[] service = RegistryStrings(set, ref d, SpdrpService);
                        list.Add(new KitNode { Id = Instance(set, ref d), Parent = Parent(d),
                            HardwareIds = RegistryStrings(set, ref d, SpdrpHardwareId),
                            Service = service.Length == 1 ? service[0] : null, Present = true });
                        uint child;
                        if (CM_Get_Child(out child, devinst, 0) == 0)
                        {
                            while (true)
                            {
                                queue.Enqueue(child);
                                uint sibling;
                                if (CM_Get_Sibling(out sibling, child, 0) != 0) break;
                                child = sibling;
                            }
                        }
                    }
                }
                finally { Marshal.FreeHGlobal(detail); }
            }
            if (interfaceCount != 1) throw new InvalidOperationException("ViGEmBus interface is absent or ambiguous.");
            return list.ToArray();
        }
        finally { SetupDiDestroyDeviceInfoList(set); SetupDiDestroyDeviceInfoList(busSet); }
    }
    public DeviceProperty ReadProperty(string instance)
    {
        IntPtr set = Open(false);
        try
        {
            DeviceInfo d = Blank();
            if (!SetupDiOpenDeviceInfo(set, instance, IntPtr.Zero, 0, ref d))
                return new DeviceProperty { Kind = PropertyKind.ReadError, NativeError = Marshal.GetLastWin32Error() };
            uint type, required; var bytes = new byte[4]; PropKey key = SessionKey;
            bool success = SetupDiGetDeviceProperty(set, ref d, ref key, out type, bytes, 4, out required, 0);
            int error = success ? 0 : Marshal.GetLastWin32Error();
            return DecodePropertyResult(success, error, type, required, bytes);
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
    }
    internal static DeviceProperty DecodePropertyResult(bool success, int error, uint type, uint required, byte[] bytes)
    {
        if (!success) return new DeviceProperty { Kind = error == ErrorNotFound ? PropertyKind.Absent : PropertyKind.ReadError,
            NativeError = error };
        if (type != DevpropUInt32 || required != 4 || bytes == null || bytes.Length < 4)
            return new DeviceProperty { Kind = PropertyKind.WrongType, NativeError = (int)type };
        return new DeviceProperty { Kind = PropertyKind.UInt32, Value = BitConverter.ToUInt32(bytes, 0) };
    }
    public void SetProperty(string instance, uint value)
    {
        if (value == 0 || String.IsNullOrWhiteSpace(instance)) throw new ArgumentException("Nonzero exact session and device required.");
        IntPtr set = Open();
        try
        {
            DeviceInfo d = Blank(); PropKey key = SessionKey;
            if (!SetupDiOpenDeviceInfo(set, instance, IntPtr.Zero, 0, ref d))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Exact present device unavailable");
            if (!SetupDiSetDeviceProperty(set, ref d, ref key, DevpropUInt32, BitConverter.GetBytes(value), 4, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Device-session assignment failed");
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
    }
    internal void RestoreAbsentTargetProperty(string instance, uint expectedAssigned, DeviceProperty prior)
    {
        if (prior == null || (prior.Kind != PropertyKind.Absent && prior.Kind != PropertyKind.UInt32) ||
            Nodes().Any(n => n.Present && String.Equals(n.Id, instance, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Cannot restore a present or ambiguously owned device.");
        DeviceProperty current = ReadProperty(instance);
        if (current.Kind == PropertyKind.ReadError && current.NativeError == ErrorNotFound) return; // Entire old instance vanished.
        if (current.Kind == prior.Kind &&
            (prior.Kind == PropertyKind.Absent || current.Value == prior.Value)) return; // Write never happened.
        if (current.Kind != PropertyKind.UInt32 || current.Value != expectedAssigned)
            throw new InvalidOperationException("Device property changed before recovery.");
        IntPtr set = Open(false);
        try
        {
            DeviceInfo d = Blank(); PropKey key = SessionKey;
            if (!SetupDiOpenDeviceInfo(set, instance, IntPtr.Zero, 0, ref d))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Non-present exact device unavailable");
            byte[] bytes = prior.Kind == PropertyKind.Absent ? null : BitConverter.GetBytes(prior.Value);
            uint type = prior.Kind == PropertyKind.Absent ? 0U : DevpropUInt32;
            if (!SetupDiSetDeviceProperty(set, ref d, ref key, type, bytes, bytes == null ? 0U : 4U, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Exact non-present property recovery failed");
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
        DeviceProperty observed = ReadProperty(instance);
        if (observed.Kind != prior.Kind || (prior.Kind == PropertyKind.UInt32 && observed.Value != prior.Value))
            throw new InvalidOperationException("Exact non-present property recovery readback failed.");
    }
    public bool ProcessMatches(int pid, long startTicks)
    {
        try { using (var p = Process.GetProcessById(pid))
            return p.StartTime.ToUniversalTime().Ticks == startTicks; }
        catch { return false; }
    }
    public bool GenerationMatches(int session, long logon)
    {
        IntPtr data = IntPtr.Zero; int bytes;
        if (session <= 0 || !WtsQuery(IntPtr.Zero, (uint)session, 25, out data, out bytes)) return false;
        try
        {
            if (data == IntPtr.Zero || bytes < Marshal.SizeOf(typeof(WtsInfoEx))) return false;
            var info = (WtsInfoEx)Marshal.PtrToStructure(data, typeof(WtsInfoEx));
            return info.Level == 1 && info.Data.SessionId == session && info.Data.LogonTime == logon;
        }
        finally { if (data != IntPtr.Zero) WTSFreeMemory(data); }
    }
    internal bool ParentChildMatches(int parent, int child)
    {
        if (Process.GetCurrentProcess().SessionId != parent) return false;
        uint actual;
        return WTSGetChildSessionId(out actual) && actual == (uint)child;
    }
}
