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

- [Official Sunshine prerelease `v2026.1018.5342`](https://github.com/LizardByte/Sunshine/releases/tag/v2026.1018.5342), source commit `3d6e1d6008bd4a24906283ab25fcd0becc0a1c07`. The previous `v2026.1015.174736` prerelease disappeared from the upstream release API and its asset URL returned 404 during exact-source CI.
- [Capture-only merge `fd45d2dd853d4f9310616112d78168226df6099c`](https://github.com/LizardByte/Sunshine/commit/fd45d2dd853d4f9310616112d78168226df6099c) is an ancestor of the release source commit by 61 commits.
- Official `Sunshine-Windows-AMD64-lite.zip` SHA-256: `5637d74c6f0d80bb133c0d6d4df7c49c663c0f860b4e96efcb9d1d9c207ea649` (60,876,058 bytes); embedded `Sunshine/sunshine.exe` SHA-256: `7200207666836abb1646831809ef7b4744d0b40c7cc5aed09ba7ebc0edc05081` (106,963,476 bytes).
- Read-only binary inspection found `external_audio`, `audio_sink`, and `stream_audio` in that executable. The release source parses the key and its Windows backend has the capture-only policy branch. This is stronger than adding an unknown key to an old binary, though actual child-session audio remains untested.
- [Official exact-source Windows CI run 39084454365](https://github.com/LizardByte/Sunshine/actions/runs/39084454365) passed its Windows-AMD64 test job: 12 `ExternalAudioTest` and 15 `WindowsAudioTest` cases. Those production-code tests substitute COM policy/device APIs and cover no default setter/reset or format mutation, no driver auto-install, explicit sink selection, missing/unplugged sink without default fallback, endpoint reactivation, and pinned capture across default changes. ChildStream did not rebuild or execute those C++ tests locally.

## Connected source path

The normal application obtains exact child identity, starts its limited child
agent, discovers child display and audio endpoints, and uses the selected active
endpoint ID in an immutable generation configuration. RDP mode 1 leaves playback
on the remote child host; parent microphone redirection stays off. ChildStream
Sunshine first receives `audio_sink = <selected ID>`, `external_audio = enabled`,
`stream_audio = disabled`, `install_steam_audio_drivers = disabled` and no
`virtual_sink`. This explicit silent preparation lets the game launch before its
render session exists. Pairing and Steam/game commands remain bound to the exact owned
process and certificate. Local-to-LAN reconfiguration preserves the selected
identity in the presenter request and a healthy game survives Sunshine recovery.
The agent observes endpoint presence again while running. When the exact game
render route is observed, the owner can select **Enable verified game audio**.
The presenter and agent recheck the route, stop only the exact owned Sunshine,
and start an immutable capture-only configuration with `stream_audio = enabled`.
The game, child session and pairing identity remain in place; Moonlight reconnects.
An idle agent monitor also checks the admitted route. Wrong, ambiguous or missing
route evidence stops the audio-enabled process; if the selected endpoint remains
available, the agent restarts Sunshine silently. Endpoint loss leaves the stream
stopped until an endpoint is reselected. A later positive observation requires a
new explicit audio-enable action. A stopped, failed or crashed agent cannot claim
continuous enforcement, and polling cannot prevent every transient leak.

The game route has a **supported owner-configured adoption path**, rather than
an automatic setter. Once the exact owned Minecraft Dungeons process starts,
the normal app requests Windows' documented `ms-settings:apps-volume` Volume Mixer
from that child desktop; the owner must confirm the window appeared there and may
choose the game's output. Child-observed friendly endpoint names are shown when
available, while all checks use stable endpoint IDs. The agent
then reconciles active Core Audio sessions on all observed render endpoints
with the durable game PID, start time, image digest, WTS session and logon
generation. It reports `WaitingForRender`, `GameRenderObserved`,
`WrongEndpoint`, `AmbiguousSession`, `ObservationIncomplete`, or
`CaptureEndpointLost` separately from Sunshine capture readiness and client
playback. A multi-process session, stale PID or failed API never becomes a
positive observation. The positive synthetic production-path fixture names
**Windows Volume Mixer per-app output to `{child-audio-2}`**, a nondefault
endpoint, with Sunshine `audio_sink` set to that same endpoint. It exercises
the presenter, controller, agent, owned game record, configuration file,
observation, explicit audio-enabled restart, idle wrong-route withdrawal,
silent reconnect and Sunshine-only recovery with unchanged game and pairing.
The status separately labels `DefaultEndpoint` and `NondefaultEndpoint`;
observing game render on the default is not evidence of child-only audio.

This does **not** establish the Windows per-app preference programmatically,
read its persisted value, prove it is scoped to the child session, or prove
the endpoint is private. Core Audio sessions show an active rendering
association; they do not prove exclusive ownership or audible Moonlight
playback. A same-user preference may influence another instance of the game.
The app changes no default or per-app preference itself, and opening Settings
without the owner's selection changes nothing. Until a designated endpoint,
its parent effects and the actual child game behavior are qualified on an
authorized machine, game audio and parent noninterference remain incomplete.

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
