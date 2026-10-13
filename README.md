# ChildStream

ChildStream is a Windows child-session and portable Sunshine proof of concept for streaming a second interactive desktop to Moonlight. It is **not ready for live installation**. The original setup changed global RDP and firewall state, downloaded an unpinned executable, and had no rollback journal. This branch disables that installer path until its architecture and recovery behavior can be validated.

Read the [architecture and security audit](docs/audit.md) and [live acceptance plan](docs/live-acceptance.md) before testing on a Windows host. The intended outcome is independent physical and remote interaction with separate capture, input, and audio; none of those hardware claims has been established by this branch.

## Offline work

From PowerShell in the repository root:

```powershell
.\tests\offline.ps1
```

This compiles and executes pure launcher logic tests. It does not create or connect a child session. `scripts/setup.ps1 -Mode Validate` runs read-only host diagnostics when a live diagnostic read is authorized. `Apply`, `Recover`, and `Uninstall` deliberately fail before modifying the host.

The launcher now uses Microsoft's documented automatic child-session authentication from the existing parent session. It does not request or persist the Windows password. It attempts to remove the previous `cred.bin`; `ChildStream.exe -resetpass` is also available after compilation. Microsoft documents exceptions for smart-card parent logon and a parent session established before child sessions were enabled. The live behavior on Windows 11 Pro build 26200 still needs verification.

An explicit **End session** action checks the child ID associated with this parent, checks that it matches the observed connected child, and then calls `WTSLogoffSession`. Closing the viewer is a different operation and does not intentionally sign out the child. Portable Sunshine startup, game/audio/controller integration, transactional installation, and complete rollback remain future work.

## Source

- `src/ChildStream.cs`: WinForms RDP ActiveX viewer and exact child-session sign-out.
- `scripts/diagnose.ps1`: read-only inventory; omits credentials and Sunshine config contents.
- `scripts/childsession-autostart.ps1`: inert guard if a legacy all-users hook still invokes it; the original script is available in Git history for audit.
- `docs/audit.md`: source behavior, risk/gap matrix, mutation inventory, recovery conditions, and prioritized plan.
- `docs/live-acceptance.md`: separate live-system test gate and evidence requirements.

MIT licensed; see [LICENSE](LICENSE).
