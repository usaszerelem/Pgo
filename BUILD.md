# Building Pgo

This solution contains two projects:

- **PgoEngine** — static library with the core obfuscation/crypto logic
- **PgoCli** — command-line front-end, links against `PgoEngine`

Both build on Windows and macOS via CMake + vcpkg.

## Prerequisites (one-time, per machine)

**Both platforms**
- CMake >= 3.16 on `PATH`
- Git (to have cloned this repo with the vendored `vcpkg/` folder)

**Windows**
- Visual Studio Build Tools (MSVC) with the C++ workload — provides `cl.exe`, `nmake`, `lib.exe`. Run everything from a "Developer Command Prompt/PowerShell for VS" so these are on `PATH`.

**Mac**
- Xcode Command Line Tools (`xcode-select --install`) — provides `clang++`, `make`.
- `pkg-config` — not preinstalled on macOS; if missing, `pip install pkgconf` gives a usable `pkg-config`/`pkgconf` binary.

**vcpkg bootstrap (one-time)**
```
# Windows
vcpkg\bootstrap-vcpkg.bat

# Mac / Linux
./vcpkg/bootstrap-vcpkg.sh -disableMetrics
```
This produces `vcpkg/vcpkg(.exe)`. You don't need to manually `vcpkg install` anything — [vcpkg.json](vcpkg.json) is a manifest, so CMake triggers the `argon2` install automatically during configure, for whichever triplet matches your host.

## Building from the command line

Each of Debug/Release gets its own build tree (`build/debug`, `build/release`) so you can have both on disk at once.

**Debug**
```
cmake -S . -B build/debug -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug --target PgoEngine   # builds the static lib alone
cmake --build build/debug --target PgoCli      # builds PgoCli (and PgoEngine, as a dependency)
```

**Release** — same, swapping `debug`->`release` and `Debug`->`Release`.

On Windows, add `-G "NMake Makefiles"` to the configure line (matches what `tasks.json` does) so the output layout is single-config like Mac's, rather than the default multi-config Visual Studio generator.

Omitting `--target` builds everything in the tree (both projects), since the root `CMakeLists.txt` does `add_subdirectory(PgoEngine)` then `add_subdirectory(PgoCli)`.

## Output locations

- `build/<debug|release>/PgoEngine/libPgoEngine.a` (Mac/Linux) or `PgoEngine.lib` (Windows)
- `build/<debug|release>/PgoCli/PgoCli` (Mac/Linux) or `PgoCli.exe` (Windows)

## Running tests

GoogleTest-based automated tests are built by default (`PGO_BUILD_TESTS`, on by default —
configure with `-DPGO_BUILD_TESTS=OFF` to skip them). `vcpkg.json` pulls in `gtest`
automatically, same as `libsodium`.

- `PgoEngineTests` exercises `pgo::obfuscateFile`/`reverseFile` directly (round-trips,
  wrong password, tampered/truncated payloads, missing files).
- `PgoCliTests` exercises `PgoCli`'s argument-parsing logic, which lives in the
  `PgoCliLib` static library (`PgoCli/Include/CommandLine.h`, `PgoCli/Source/CommandLine.cpp`)
  so it can be linked into a test binary without pulling in `main()`.

```
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

## Building via VS Code

Use **Terminal -> Run Task**, or press **Cmd+Shift+B** (Mac) / **Ctrl+Shift+B** (Windows) to get a picker with all four build tasks:
- `Build Debug (PgoCli)` — configures `build/debug` (if not already) then builds `PgoCli` (+ `PgoEngine`)
- `Build Release (PgoCli)` — same for `build/release`
- `Build Debug (PgoEngine)` — configures `build/debug` (if not already) then builds just the `PgoEngine` static library
- `Build Release (PgoEngine)` — same for `build/release`

The `PgoCli` tasks are also wired as `preLaunchTask` in `.vscode/launch.json`, so pressing F5 with the "Debug (PgoCli)" or "Release (PgoCli)" configuration selected builds and launches automatically, with the debugger backend chosen per OS (`cppvsdbg` on Windows, `lldb` via `cppdbg` on Mac).
