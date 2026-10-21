# hidmaestro-client

Native Rust client for one HIDMaestro `xbox-360-wired` controller on Windows
x64. It calls Win32 directly; no .NET runtime, SDK process or custom driver
is required by the client.

Requires administrator privileges and both HIDMaestro v2.0.0 driver
packages, version **2.0.0.2201**: `hidmaestro.inf` and `hidmaestro_xusb.inf`.
Install those separately using the upstream release instructions. This crate
does not install drivers, create signing certificates or change Windows
security settings. Driver source/protocol is pinned to upstream commit
`30b8faf0f7de746f249edc5f1520eaa0440965cf`. The client speaks driver
protocol 4 (the v2.0.0 version contract) and uses protocol 5 removal when
the driver offers it; creation fails if a started driver does not serve 4.

```rust,no_run
use hidmaestro_client::{Buttons, Controller, State};

fn main() -> hidmaestro_client::Result<()> {
    let mut controller = Controller::create()?;
    controller.submit(&State {
        buttons: Buttons::A,
        left_trigger: 255,
        right_trigger: 255,
        ..State::default()
    })?;
    controller.submit(&State::default())?;
    controller.close()
}
```

Stick axes are `i16`, centered on zero; positive Y points up. Triggers are
independent `u8` values, 0 through 255. Combine buttons with `|`. Opposite
D-pad directions are rejected. Guide is sent to the driver but the standard
`XInputGetState` API does not report Guide.

Only one client can own controller index 0. Creation refuses conflicting
Global mappings without a valid ownership journal, or an existing foreign
`HKLM\SOFTWARE\HIDMaestro\Controller0`. The client also writes the identity
entry `HKLM\SOFTWARE\HIDMaestro\Identity\HM_RUST_CLIENT_0`, through which
both drivers find the controller's index before they start.
The library creates its own HID root node and XUSB software device. It does
not sweep devices by VID/PID or edit shared OEM/GameInput mappings.

`close` sends neutral state, removes the client's devices and configuration,
and reports cleanup failures. The HID device is removed with a removal query
first; when a program holding it refuses, the driver fails the device as an
unplug does, instead of leaving its HID child without a driver. `Drop` attempts the same cleanup but cannot
return an error; prefer explicit `close`. If another program changes the
configuration, cleanup preserves it and returns an error. Do not edit the
client's configuration while it is running.

On forced process termination, Windows closes the XUSB software-device
handle, removing the controller from XInput. The HID root node and ownership
record can remain until the next successful `create`, which removes only
the client's recorded root identity. Changed ownership/configuration causes
an error and is preserved.
The actual companion ID is recorded separately under
`HKLM\SOFTWARE\HIDMaestroRustClient\Controller0`. The journal remains after
close if another process retains transport objects, so the next session can
verify ownership before reopening them. Do not edit either ownership record.
A configuration left by the previous version of this client, built for the
v1.12.0 drivers, is recognised and removed the same way.

For an application with a separate elevated lifecycle helper,
`Controller::take_writer` delegates input publication and disables the
controller's `submit`. The returned `Writer` exposes borrowed handles for
the input section and its two events. Duplicate only those handles into the
application, then import them with `Writer::from_handles`; driver mappings
do not need broader access permissions. Closing the controller publishes
neutral and makes the delegated writer's `submit` fail. Imported writers are
not stopped this way: there must be one active writer, and every imported
writer must be stopped and dropped before closing or dropping the
controller, or the drivers may read torn frames. Cleanup publishes
neutral using the latest shared sequence, including recovery from a writer
terminated midway through a frame.

If cleanup fails after releasing the transport, the controller retains its
ownership lease and `Drop` retries removal and configuration cleanup.

The pinned XUSB driver can retain mappings while another process keeps
cached XInput handles without polling again. After removing the old devices,
the next session reopens the owned mappings and resets input, output,
acknowledgements and events. Unowned objects, changed ownership records,
remaining device nodes and existing owner pipes are still conflicts.

## Build and checks

With a Windows Rust MSVC toolchain and linker installed:

```powershell
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release --example xinput
```

From an elevated terminal, run the hardware check explicitly:

```powershell
cargo run --release --example xinput -- verify
```

It checks 30 states through `XInputGetState`: buttons and all D-pad positions,
both sticks including their limits, individual and simultaneous LT/RT,
neutral, and the original XInput slots after `close`. It requires a free
XInput slot and no other controller connecting/disconnecting during the test.

For manual crash verification:

```powershell
cargo run --release --example xinput -- hold
```

After it prints `holding A`, terminate the printed PID. `probe` lists current
XInput states without creating a device or requiring elevation:

```powershell
cargo run --release --example xinput -- probe
```

The additional hardware tests create/remove devices, exercise rollback,
check exclusivity and preserve foreign/changed configuration. They are
ignored by ordinary `cargo test`. Run only in an elevated terminal, serially:

```powershell
cargo test --lib -- --ignored --test-threads=1
```

Creation, XInput state delivery, explicit close, Drop, setup rollback,
forced termination and subsequent recovery were checked on Windows x64
build 26300 with the pinned driver packages. Compatibility with games,
Steam Input and anti-cheat software, latency and other Windows builds have
not been measured. Rumble delivery, other controller profiles and Razer
integration are outside this version.

See [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt) for the upstream license.
