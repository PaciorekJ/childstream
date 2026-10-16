# Product runtime map at this source increment

`ChildStream.exe` currently invokes the WinForms RDP ActiveX viewer, credential-free
child lifecycle, exact sign-out and read-only Sunshine readiness action. The v6
feasibility probe is a separate executable with approval-gated Stage A/B actions.
`setup.ps1` invokes read-only validation and rejects live Apply/Recover/Uninstall.

```text
parent console -> ChildStream.exe viewer -> ActiveX child connection
               -> ChildSessionLifecycle -> exact child ID + WTS logon generation
               -> sign-out intent -> exact child logoff (only by explicit action)

separate feasibility probe -> v6 isolated plan/journal -> approved Stage A/B

candidate product path (not enabled):
verified child -> installer-owned interactive-token Task Scheduler task
               -> RunEx(target child ID) -> ChildStream.exe -child-agent
               -> bounded same-user pipe handshake -> exact PID/session/generation/hash
               -> child-side Sunshine/audio/Steam controller (not connected)
```

The child agent currently performs identity verification and waits on its parent
pipe. It does not start Sunshine, Steam, a game, or a network listener. The
Task Scheduler task is not installed. `RunEx` can return without starting a
task, so the handshake and exact process check are mandatory; this candidate
mechanism needs a real Stage B Windows test. The parent-to-child transition,
Sunshine coexistence, Moonlight LAN route, graphics/input/audio behavior and
installer completion remain open product work. No child desktop or stream has
been demonstrated.

The official [Task Scheduler RunEx contract](https://learn.microsoft.com/en-us/windows/win32/taskschd/registeredtask-runex)
describes session-targeted demand execution and its non-starting success cases.
The [child-session contract](https://learn.microsoft.com/en-us/windows/win32/termserv/child-sessions)
describes the ActiveX loopback connection. Neither document proves the
candidate works on the intended Windows 11 Pro host.
