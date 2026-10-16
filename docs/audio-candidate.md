# Windows x64 audio candidate

This is an **unsigned, hardware-unverified engineering package**. The user ZIP has
one entry application, `ChildStream.exe`. Extract the whole ZIP to a persistent
folder and open that executable as a standard user. Its first-run installation
screen reads `bundle.json`, verifies the contained ChildStream candidate,
bootstrap and Sunshine archive, carries their hashes internally, and prepares a
read-only plan. The user must review and approve that exact plan before Windows
UAC for owned-file installation. Feature enablement and LAN access are separate
transactions. The package manifest proves internal consistency only; review the
published outer ZIP digest independently before running any unsigned executable.

`scripts/build-candidate.ps1` builds the source/evidence candidate from the
exact committed SHA. `scripts/build-user-package.ps1` combines that candidate
with the pinned Sunshine archive, executables, Sunshine LICENSE and NOTICE,
and verifies an extracted user bundle through the production `ProductBundle`
admission path. The CI artifact is downloadable for review; it is not a signed
release or evidence of a live installation.

## Qualified dependency

- [Official Sunshine prerelease `v2026.1015.174736`](https://github.com/LizardByte/Sunshine/releases/tag/v2026.1015.174736), source commit `178a0467da1dde750b182be4ae10ff8f8245ad01`.
- [Capture-only merge `fd45d2dd853d4f9310616112d78168226df6099c`](https://github.com/LizardByte/Sunshine/commit/fd45d2dd853d4f9310616112d78168226df6099c) is an ancestor of the release source commit by 49 commits.
- Official `Sunshine-Windows-AMD64-lite.zip` SHA-256: `35fa21069c314896e9b476e16e42fe4d60986dc3926b54e80d1c693e40d314cc`; embedded `Sunshine/sunshine.exe` SHA-256: `424cb1bbfe994c7676ff03957f1b3e1e79d218264677ec0b8959b5c809523c8c`.
- Read-only binary inspection found `external_audio`, `audio_sink`, and `stream_audio` in that executable. The release source parses the key and its Windows backend has the capture-only policy branch. This is stronger than adding an unknown key to an old binary, though actual child-session audio remains untested.
- [Official exact-source Windows CI run 38780282332](https://github.com/LizardByte/Sunshine/actions/runs/38780282332) passed its Windows-AMD64 test job: 12 `ExternalAudioTest` and 15 `WindowsAudioTest` cases. Those production-code tests substitute COM policy/device APIs and cover no default setter/reset or format mutation, no driver auto-install, explicit sink selection, missing/unplugged sink without default fallback, endpoint reactivation, and pinned capture across default changes. ChildStream did not rebuild or execute those C++ tests locally.

## Connected source path

The normal application obtains exact child identity, starts its limited child
agent, discovers child display and audio endpoints, and uses the selected active
endpoint ID in an immutable generation configuration. RDP mode 1 leaves playback
on the remote child host; parent microphone redirection stays off. ChildStream
Sunshine receives `audio_sink = <selected ID>`, `external_audio = enabled`,
`stream_audio = enabled`, `install_steam_audio_drivers = disabled` and no
`virtual_sink`. Pairing and Steam/game commands remain bound to the exact owned
process and certificate. Local-to-LAN reconfiguration preserves the selected
identity in the presenter request and a healthy game survives Sunshine recovery.
The agent observes endpoint presence again while running; loss blocks pairing
and new game actions and exposes exact-owned stream recovery.

**Game render routing is a remaining source/product gap.** Sunshine's new mode
captures an endpoint but does not route game playback to it. For a game using
the observed child default endpoint, Windows' normal render selection may
produce sound there; this is not evidence that the default is session-private.
A nondefault selected endpoint is valid for capture but requires an established
application or external mixer route. ChildStream does not yet provision or verify
such a route and does not silently change any Windows default or per-app audio
preference. Same-user per-app preferences may affect another instance of the
same executable. If a designated child-only endpoint and application route
cannot be established without parent effects, the audio requirement remains
unsatisfied despite the capture-only backend.

## Separate physical acceptance

Stage A feature enablement and Stage B independent-desktop interaction have not
run. The intended connected host remains blocked by ordinary-RDP exposure and
protected parent-logon disruption. After a separately authorized target passes
those gates, verify the exact child process, endpoint and game render sessions;
test Moonlight host playback on/off, first start, stop/reconnect and endpoint
reactivation while listening to the parent desktop. Then verify GPU capture,
native Sunshine coexistence, Fire TV custom port access, and two child-only
controllers. No controller reports are enabled in this candidate. A source,
fixture, or upstream CI pass does not certify these physical effects.
