# Pgo Architecture & Design Specification

This document explains **how Pgo (Pretty Good Obfuscation) is built and why**. Where the
[User Guide](UserGuide.md) tells you how to run `PgoCli`, this document is for anyone
maintaining, extending, reviewing, or auditing the codebase — it walks through every
significant design decision, the alternatives that were available, and the reasoning that
led to the choice actually made.

## Contents

1. [Purpose and scope](#1-purpose-and-scope)
2. [Goals and non-goals](#2-goals-and-non-goals)
3. [System overview](#3-system-overview)
4. [Component architecture](#4-component-architecture)
5. [Cryptographic design](#5-cryptographic-design)
6. [Password acquisition design](#6-password-acquisition-design)
7. [Command-line interface design](#7-command-line-interface-design)
8. [Error handling philosophy](#8-error-handling-philosophy)
9. [Build system design](#9-build-system-design)
10. [Testability design](#10-testability-design)
11. [Cross-platform considerations](#11-cross-platform-considerations)
12. [Known limitations and trade-offs](#12-known-limitations-and-trade-offs)
13. [Future directions](#13-future-directions)

## 1. Purpose and scope

Pgo takes an arbitrary file and a password, and produces a second file that only someone
who knows the password can turn back into the original. That's the entire product
requirement. Everything in this document follows from trying to satisfy that requirement
**correctly** (an attacker without the password should not be able to recover the
plaintext, nor tamper with it undetected) with the **smallest reasonable amount of code**
running on top of a well-reviewed cryptography library, while remaining pleasant to use
from a terminal or a script.

## 2. Goals and non-goals

| Goal                                                                          | Non-goal                                                                                                                             |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Confidentiality and integrity of file contents under a chosen password        | Protecting metadata (filenames, file sizes, timestamps) — Pgo only touches the bytes you point it at                                 |
| Resistance to offline password-guessing at rest                               | Resistance to a compromised machine while Pgo is _running_ (keyloggers, memory-dumping malware, etc.)                                |
| A single static binary's worth of dependencies, portable to Windows and macOS | A GUI, a network service, or multi-user key management                                                                               |
| Safe-by-default behavior (fail closed, scrub secrets, no password on the CLI) | Configurability of every cryptographic parameter from the command line (deliberately fixed, see [§5.3](#53-key-derivation-argon2id)) |
| Constant, chunk-bounded memory use when encrypting/decrypting, independent of file size (streaming, see [§5.9](#59-streaming-and-chunk-framing)) | Resumable or parallel processing of a single file — each file is still one sequential stream |
| Being straightforward enough to read end-to-end in one sitting                | An on-disk format versioned/negotiated per file (chunk size and cost parameters are fixed at compile time, see [§12](#12-known-limitations-and-trade-offs)) |

These constraints explain a recurring theme below: at almost every fork in the road, Pgo
chose the option with **less mechanism**, provided it didn't compromise the confidentiality/
integrity goal.

## 3. System overview

```
                      ┌─────────────────────────────┐
                      │           PgoCli            │   command-line entry point
                      │   (Source/main.cpp)         │   (interactive prompt, echo
                      │                             │    suppression, wiring)
                      └───────────┬─────────────────┘
                                  │ links against
                 ┌────────────────┼───────────────────┐
                 ▼                                    ▼
      ┌──────────────────────┐              ┌───────────────────────┐
      │      PgoCliLib       │              │      PgoEngine        │
      │ (CommandLine.h/.cpp) │              │ (PgoEngine.h/.cpp)    │
      │ arg parsing, argfile │              │ obfuscateFile /       │
      │ expansion, password- │              │ reverseFile           │
      │ file slicing         │              │                       │
      └──────────────────────┘              └───────────┬───────────┘
                                                        │ links against
                                                        ▼
                                              ┌──────────────────────┐
                                              │ unofficial-sodium    │  (libsodium, via vcpkg)
                                              │ Argon2id, XChaCha20- │
                                              │ Poly1305, CSPRNG     │
                                              └──────────────────────┘

      ┌─────────────────────┐              ┌──────────────────────┐
      │ PgoEngineTests      │              │   PgoCliTests        │
      │ (GoogleTest, links  │              │ (GoogleTest, links   │
      │ PgoEngine directly) │              │  PgoCliLib directly) │
      └─────────────────────┘              └──────────────────────┘
```

Three independently linkable units come out of this: `PgoEngine` (a reusable crypto
library with no CLI-specific concepts in it at all), `PgoCliLib` (the CLI's argument-
parsing brain, deliberately free of interactive I/O and crypto calls), and `PgoCli` (a
thin `main()` that wires the two together with interactive prompting). See
[§4](#4-component-architecture) for why the boundaries fall exactly there.

## 4. Component architecture

### 4.1 PgoEngine

`PgoEngine.h` / `PgoEngine.cpp` expose exactly two functions —
`pgo::obfuscateFile` and `pgo::reverseFile` — plus the `EngineConfig` struct that carries
a password and Argon2id cost parameters. Everything else in the `.cpp` file (salt
generation, key derivation, payload assembly/parsing, the `ScopedZero` RAII guard) lives
in an anonymous namespace: it is implementation detail that no caller, including PgoCli,
is meant to depend on.

**Why a library and not just code inside PgoCli:** the crypto logic has no dependency on
argument parsing, terminals, or `main()`. Keeping it as a standalone static library means
(a) it can be linked directly into a test binary with zero test-only scaffolding inside
the production code, and (b) a future consumer (a GUI, a batch tool, a different CLI)
could link `PgoEngine` without dragging in `PgoCli`'s argument parsing or interactive
prompting at all.

**Why a two-function, four-argument surface (`input path, output path, config, error`)
rather than something more granular** (e.g., separate `deriveKey`/`encrypt`/`decrypt`
calls exposed publicly): every caller of this library wants the same thing — "take this
file, give me that file, tell me if it failed." Exposing the intermediate steps would
let a caller assemble them incorrectly (e.g., reusing a nonce, or skipping the AEAD tag
check) with no compensating benefit, since no current or anticipated caller needs
anything finer-grained. This is deliberately not a general-purpose crypto toolkit; it is
two file-shaped verbs.

### 4.2 PgoCliLib

`PgoCli/Include/CommandLine.h` and `PgoCli/Source/CommandLine.cpp` hold
`parseCommandLine`, `expandArgs`, `readArgFile`, `extractPasswordFromFile`, and
`printUsage` — i.e., every piece of `PgoCli` that is pure logic over strings and files,
with no interactive I/O.

**Why this was split out of `main.cpp` (history):** originally all of this lived in an
anonymous namespace inside `main.cpp`. That is a perfectly normal way to write a small
CLI, but it made the parsing logic unreachable from a separate test binary — an anonymous
namespace is only visible within its own translation unit, and nothing outside
`main.cpp` could call `parseCommandLine` to assert on its behavior without either linking
`main.cpp` directly (which would pull in a competing `main()`) or reflecting the logic
into the test file (which would test a copy, not the real thing). Extracting these
functions into their own translation unit with a header, behind a static library target,
resolved that without changing a single line of parsing behavior. This is the standard
"a `main()` should be nearly empty" pattern: the thinner `main.cpp` is, the less of the
program is only exercisable by actually running the executable.

**Why `ScopedZeroString`, `ScopedEchoDisabled`, and `promptForPassword` stayed in
`main.cpp` instead of moving too:** they are interactive/OS-facing (terminal echo control
via `termios`/`Console` APIs, reading from `std::cin`). Unit-testing "did this correctly
toggle terminal echo" has poor cost/benefit — it would require faking a TTY — while the
thing worth testing (does `-passwordfile`/`-passwordoffset`/`-passwordlength` slice bytes
correctly, does `-argfile` expand tokens correctly) is already fully covered by testing
`CommandLine.cpp` in isolation. Drawing the boundary at "testable pure logic" vs.
"thin interactive glue" avoids both under- and over-testing.

### 4.3 PgoCli

`main.cpp` is deliberately small: expand arguments, parse them, obtain a password
(prompt or file), validate the parsed options, and call into `PgoEngine`. Every branch
that can fail throws `std::invalid_argument`, caught once at the bottom of `main()`,
which prints usage plus the specific message and returns exit code `1`. See
[§8](#8-error-handling-philosophy) for why a single catch site was chosen over
per-branch error handling.

### 4.4 Tests

`Tests/PgoEngineTests` and `Tests/PgoCliTests` are separate GoogleTest binaries, one per
library, rather than a single combined test executable. See [§10](#10-testability-design)
for the reasoning.

## 5. Cryptographic design

### 5.1 Threat model

Pgo's design target is: **an attacker who obtains the obfuscated output file, and nothing
else, should not be able to recover the plaintext or produce a modified plaintext that
verifies, except by guessing the password.** Concretely, this covers a lost laptop, a
stolen backup, or a file sent over an untrusted channel.

Explicitly out of scope (see also [§2](#2-goals-and-non-goals)):

- An attacker who can run code on the machine while you type your password, or while
  `PgoCli` is executing (keyloggers, process memory inspection, `/proc` scraping).
  No user-space program can fully defend against a co-resident attacker with that level
  of access.
- Side-channel leakage through timing/power analysis of the underlying crypto primitives
  — this is delegated entirely to libsodium, which is written with these concerns in mind
  (see [§5.2](#52-choice-of-libsodium)).
- Multi-user or multi-key scenarios (key rotation, revocation, sharing a file with several
  recipients each having their own password). Pgo is single-password, single-recipient by
  design; see [§13](#13-future-directions).

Everything from here down is justified against that single-attacker-with-the-file model.

### 5.2 Choice of libsodium

Pgo calls into libsodium (`unofficial-sodium` in vcpkg) for every cryptographic
operation: `sodium_init`, `randombytes_buf`, `crypto_pwhash`,
`crypto_aead_xchacha20poly1305_ietf_{encrypt,decrypt}`, and `sodium_memzero`. Three
reasons drove this over, say, OpenSSL or a hand-rolled implementation:

1. **Misuse-resistant API surface.** libsodium deliberately exposes few knobs and
   sensible constants (`crypto_aead_xchacha20poly1305_ietf_{NPUBBYTES,KEYBYTES,ABYTES}`)
   rather than a general-purpose cipher/mode/padding matrix a caller could configure
   incorrectly. Pgo's own two-function API (see [§4.1](#41-pgoengine)) mirrors that
   philosophy at one layer up.
2. **A single dependency covers both primitives Pgo needs** — the Argon2id KDF and an
   AEAD cipher — instead of pulling in separate libraries (e.g., a standalone Argon2
   implementation plus a general crypto library) with independent update cadences and
   API idioms.
3. **Portability.** libsodium builds cleanly on Windows (MSVC) and macOS/Linux, matching
   Pgo's own cross-platform goal, and is available pre-packaged as a vcpkg port, fitting
   the build system described in [§9](#9-build-system-design).

Never implementing cryptographic primitives by hand is a deliberate, standing decision —
"don't write your own crypto" is not a style preference here, it's load-bearing for the
entire security goal in [§2](#2-goals-and-non-goals).

### 5.3 Key derivation: Argon2id

`deriveKey` (in `PgoEngine.cpp`) calls `crypto_pwhash` with
`crypto_pwhash_ALG_ARGON2ID13`. Argon2id was chosen, specifically, over:

- **A fast, non-memory-hard hash (SHA-256, etc.):** trivially parallelizable on GPUs/ASICs,
  so an attacker with the obfuscated file can attempt billions of password guesses per
  second. A memory-hard function forces every guess to pay the same
  time-_and_-memory cost a legitimate user pays, which collapses that advantage.
- **Argon2i or Argon2d specifically:** Argon2i is optimized against side-channel
  (cache-timing) attacks but is more vulnerable to certain time-memory trade-off attacks;
  Argon2d is the reverse. Argon2id is a hybrid (data-independent addressing for part of
  the pass, data-dependent for the rest) that the Argon2 designers and the RFC 9106
  guidance recommend as the general-purpose default — Pgo has no reason to deviate from
  that default, since it isn't defending a specialized threat model that would favor one
  side of that trade-off over the other.
- **bcrypt/scrypt:** libsodium exposes Argon2id as its modern, recommended
  `crypto_pwhash` algorithm; picking it avoids taking on a second KDF family for no
  benefit, and Argon2 (the PHC winner) has had more recent cryptanalytic attention than
  bcrypt.

`EngineConfig::tCost`/`mCost` (time cost / memory cost) are **not exposed on the CLI**.
This is deliberate: every parameter that affects how a payload is decrypted must be
derivable from the file itself or supplied identically by the user on both `obfuscate`
and `reverse` — the salt achieves this by being stored in the payload
([§5.5](#55-on-disk-payload-format)), but `tCost`/`mCost` are _not_ stored in the payload,
so if they were user-configurable a user could obfuscate a file and then be unable to
reverse it having forgotten the cost parameters they used. Fixing them at compile time
(and lowering them in Debug builds purely so iterative manual testing isn't slow, see
[§9.4](#94-debug-vs-release-cost-parameters)) removes an entire class of "I can never
open this file again" user error, at the cost of not being tunable per-file. If
configurability is ever added (see [§13](#13-future-directions)), the parameters would
need to move into the on-disk payload alongside the salt, not stay CLI-only.

### 5.4 Authenticated encryption: XChaCha20-Poly1305 (streamed)

`encryptStream`/`decryptStream` use `crypto_secretstream_xchacha20poly1305_*`, libsodium's
chunked construction built on top of XChaCha20-Poly1305, rather than a single
`crypto_aead_xchacha20poly1305_ietf_{encrypt,decrypt}` call over the whole file (the
original design, before streaming support was added — see
[§5.9](#59-streaming-and-chunk-framing) for the chunking details). Breaking down each
part of the current choice:

- **Streamed, not one-shot.** A single AEAD call needs the entire plaintext (to encrypt)
  or ciphertext (to decrypt) resident in memory at once, since its authentication tag
  covers the whole message as one unit. `crypto_secretstream` instead authenticates a
  sequence of independently-verifiable chunks derived from one key, so a file can be
  read/encrypted or decrypted/written one chunk at a time in constant memory, regardless
  of file size — see [§5.9](#59-streaming-and-chunk-framing).
- **Authenticated (AEAD), not a bare stream/block cipher.** A bare cipher (e.g. plain
  ChaCha20 or AES-CTR with no MAC) would decrypt _any_ ciphertext, corrupted or not, into
  some plaintext-shaped bytes with no way to detect tampering — silently returning
  garbage instead of failing is worse than failing loudly. Poly1305 authentication (now
  applied per chunk rather than once over the whole file) means `reverseFile` can _fail
  closed_: a wrong password or a modified file causes decryption to reject the input
  outright (see [§5.8](#58-failure-semantics-fail-closed-authentication)), rather than
  writing corrupted output that looks like it might have worked.
- **ChaCha20, not AES.** ChaCha20 has fast, constant-time software implementations
  without relying on hardware AES acceleration (AES-NI) being present. Since Pgo doesn't
  control what hardware it runs on (a build farm VM, an older machine, etc.), a cipher
  that's fast and safe in pure software avoids a class of timing side-channel risk that
  table-based AES software fallbacks are prone to.
- **The "X" (extended nonce), specifically.** Standard ChaCha20-Poly1305 (IETF variant)
  has a 96-bit (12-byte) nonce. Pgo generates a fresh random stream header, embedding the
  equivalent of a nonce, independently for every `obfuscateFile` call (see
  [§5.6](#56-salt-and-nonce-generation-and-uniqueness)) rather than maintaining a counter
  across calls — there's no persistent state to track nonce usage between invocations of
  a stateless CLI tool. With a random 96-bit nonce, the birthday bound means collisions
  become a meaningful risk after roughly billions of encryptions under the same key;
  XChaCha20's 192-bit (24-byte) nonce space (`kHeaderSize =
  crypto_secretstream_xchacha20poly1305_HEADERBYTES`) pushes that bound astronomically
  far out, so "just generate a random header every time, don't track state" is safe by
  construction rather than something that needs auditing against a call-count budget.

### 5.5 On-disk payload format

```
[ salt (16 bytes) | stream header (24 bytes) | chunk 1 | chunk 2 | ... | final chunk ]
```

Each chunk is `ciphertext + kStreamTagSize (17) bytes of AEAD tag`, corresponding to at
most `kChunkSize` (64 KiB) bytes of plaintext; see [§5.9](#59-streaming-and-chunk-framing)
for how chunks are produced and verified.

- **Self-contained, no sidecar metadata file.** `reverseFile` only needs the password and
  the obfuscated file itself — it doesn't need to be told which salt or stream header was
  used, because both are read back out of the start of the very file it's decrypting
  (`readSalt`, then the header read directly in `decryptStream`). This matches the CLI's
  usage model: a single file is the unit users copy, back up, or send to someone else,
  and it would be easy to lose a separate metadata file in that process but much harder
  to lose bytes _inside_ the file you're already carrying around.
- **Salt and stream header are stored in plaintext, deliberately.** Neither needs to be
  secret — salt's job is only to make precomputed dictionary/rainbow-table attacks
  useless by ensuring each file's key derivation is unique even under a repeated
  password, and the header's job is only to ensure the keystream is never reused under
  the same key. Confidentiality and integrity both come entirely from the _password_ via
  Argon2id and the per-chunk AEAD tags, not from hiding the salt/header — so storing them
  in the clear costs nothing.
- **No additional authenticated data (AAD).** Every `crypto_secretstream_..._push`/`_pull`
  call is made with `nullptr, 0` for AAD. AAD exists to bind ciphertext to metadata stored
  _outside_ the ciphertext (e.g., a header the format wants authenticated but not
  encrypted). Pgo's format has no such external metadata beyond the salt/header, which
  are already outside the AEAD envelope by construction and don't themselves need
  cryptographic binding beyond "the file decrypts correctly with them or it doesn't" — so
  there was nothing for AAD to usefully protect here. What a one-shot design would have
  needed AAD for — binding auxiliary data to the ciphertext — is instead handled by each
  chunk's tag byte (`TAG_MESSAGE`/`TAG_FINAL`) being itself part of what's authenticated;
  see [§5.9](#59-streaming-and-chunk-framing).
- **Chunk size is a compile-time constant, not stored in the payload.** Unlike the salt
  and stream header, `kChunkSize` isn't written to disk anywhere — `decryptStream` reads
  fixed-size chunks based on the constant compiled into the binary doing the decrypting.
  This works because both sides of any given round-trip use the same build, but it does
  mean the payload format is only self-describing for the parts that vary per file (salt,
  header); see [§12](#12-known-limitations-and-trade-offs) for the resulting compatibility
  constraint.

### 5.6 Salt and nonce generation and uniqueness

`generateSalt` calls `generateRandomBytes`, which wraps libsodium's `randombytes_buf` (a
CSPRNG), rather than anything platform-specific or predictable (e.g., a timestamp, a
counter, `rand()`). The equivalent nonce material for the stream itself is no longer
generated by Pgo's own code at all — `crypto_secretstream_xchacha20poly1305_init_push`
generates the random stream header internally (also via libsodium's CSPRNG) as part of
initializing the stream, so `encryptStream` only has to write that header out, not
generate it. Predictable salts would reintroduce the precomputation attacks salts exist
to prevent; predictable or reused nonces under the same key are catastrophic for a
stream cipher (XORing two ciphertexts encrypted with the same key/nonce cancels the
keystream and leaks the plaintext XOR). Using the OS/library CSPRNG for both the salt and
the stream header, every time, is the only choice that doesn't require Pgo to reason
about _how_ predictable is "predictable enough to matter" — it simply removes the
question.

### 5.7 Memory hygiene (`ScopedZero` / `ScopedZeroString`)

Derived keys and the reusable plaintext chunk buffer in `encryptStream`/`decryptStream`
(both via `PgoEngine.cpp`'s `ScopedZero`), and password strings (`main.cpp`'s
`ScopedZeroString`), are wrapped in RAII guards that call `sodium_memzero` on
destruction — including on exception-unwind paths, since both engine functions and
`main()` operate inside `try`/`catch` blocks that can unwind through these scopes. The
plaintext chunk buffer is wrapped once, outside the chunk loop, rather than re-wrapped
per iteration: it's the same buffer reused (and overwritten) on every chunk, so one guard
scrubbing it at function exit is sufficient to keep the last chunk's contents from
lingering after the function returns or throws.

**Why RAII instead of zeroing at the end of each function:** the whole point of scrubbing
secrets is to shrink the window they spend resident in memory after they're no longer
needed, including on error paths. A manual "zero it right before `return`" at the bottom
of a function does nothing to protect the exception path, and is easy to forget on a
newly added early `return`/`throw`. Tying the zeroing to scope exit via a destructor
means every exit path — including ones added later by someone who has never read this
paragraph — is covered automatically, which is exactly the property you want for a
security-relevant cleanup action.

**Why `sodium_memzero` and not `memset`:** compilers are permitted to (and do)
optimize away a plain `memset` of a buffer that is never read again afterward, since from
the compiler's point of view it's dead code. `sodium_memzero` is implemented to defeat
that optimization, so the zeroing actually survives into the compiled binary.

### 5.8 Failure semantics (fail-closed authentication)

`decryptStream` treats a non-zero return from `crypto_secretstream_xchacha20poly1305_pull`
for any chunk as an unconditional failure (`throw std::runtime_error("integrity check
failed")`), and stops at the first such chunk rather than continuing to process (and
authenticate) later ones. Both `obfuscateFile` and `reverseFile` funnel every exception —
I/O errors, a too-small payload, a failed decrypt — through the same `catch` block into a
`bool` return plus an `error` string (see [§8](#8-error-handling-philosophy)). The
deliberate effect: **a wrong password and a corrupted/tampered file are indistinguishable
to the caller**, both simply "failed, here's why" (both surface as "integrity check
failed"). This is correct behavior for an AEAD scheme (there is no cryptographic way to
tell "right key, corrupted ciphertext" apart from "wrong key" without leaking information
that would itself weaken the scheme against a guessing attacker), and it's called out
explicitly in the [User Guide's security section](UserGuide.md#security-considerations)
so it isn't mistaken for a bug.

Truncation ("truncated payload: missing final chunk") and trailing-data ("unexpected
trailing data after final chunk") are reported as **distinct** error messages rather than
folded into "integrity check failed," and this is not an inconsistency with the point
above: those two checks are purely about the *shape* of the byte stream (did a
`TAG_FINAL` chunk ever arrive; is there anything left in the input after it did) and are
evaluated identically regardless of whether the key is right or wrong — they leak
nothing about the password, only about whether the file the attacker already possesses
has been cut short or had bytes appended to it, both of which are directly observable
from the file's size regardless of what Pgo reports. See
[§5.9](#59-streaming-and-chunk-framing) for how these two checks work.

### 5.9 Streaming and chunk framing

`encryptStream`/`decryptStream` (`PgoEngine.cpp`) replace what was originally a single
`readFileBytes`/`buildPayload`/`writeFileBytes` sequence operating on one in-memory
buffer. Instead, `obfuscateFile`/`reverseFile` open `std::ifstream`/`std::ofstream`
handles and hand them to these functions, which loop over the file one chunk at a time.

- **Chunk size (`kChunkSize = 64 * 1024`).** Chosen as a middle ground: large enough that
  the fixed 17-byte-per-chunk AEAD tag overhead (`kStreamTagSize =
  crypto_secretstream_xchacha20poly1305_ABYTES`) and the fixed cost of each
  `push`/`pull` call are negligible relative to the data processed, small enough that
  peak memory use (a small, constant multiple of `kChunkSize`, not tied to file size) is
  clearly a non-issue on any machine Pgo targets. There is no measured performance
  tuning behind the exact value — it is a reasonable default for the "documents,
  configs, small-to-medium-to-large assets" use case, not a claim of optimality for every
  workload.
- **Marking the last chunk (`TAG_FINAL` vs. `TAG_MESSAGE`).** `crypto_secretstream`
  requires every chunk to be pushed with an explicit tag; Pgo uses `TAG_MESSAGE` for
  every chunk except the last, and `TAG_FINAL` for the one that consumes the last byte
  of input (including a single zero-length `TAG_FINAL` chunk for an empty file).
  `encryptStream` determines "is this the last chunk" by calling `input.peek()`
  immediately after reading each chunk: if the stream has no more bytes available, the
  chunk just read is final. This peek-based check (rather than, say, checking the input
  file's size up front) works uniformly whether or not the file size happens to be an
  exact multiple of `kChunkSize`, without needing a separate code path for that edge
  case.
- **Detecting truncation and trailing data.** `decryptStream` reads chunks in
  `kChunkSize + kStreamTagSize`-byte pieces and checks, for each one, whether its tag
  came back as `TAG_FINAL`. If the input runs out (a short or zero-byte read) before a
  `TAG_FINAL` chunk is seen, that's a truncated file — the real final chunk is missing.
  Conversely, once a `TAG_FINAL` chunk is processed, `decryptStream` checks that the
  input is now genuinely exhausted (`input.peek()` returns EOF); if not, something was
  appended after the legitimate end of the stream. Both checks exist because
  `crypto_secretstream` on its own only authenticates the chunks it's given — it has no
  way to know whether the *caller* stopped feeding it chunks too early or fed it extra
  ones, so Pgo has to track "did we see exactly one final chunk, with nothing after it"
  itself.
- **Atomic output via a temporary file.** Because chunks are written to `-output` as
  soon as each one is decrypted and authenticated (rather than only after the entire
  payload was validated in memory, as the original one-shot design did), a failure on a
  *later* chunk — wrong password, tampering, truncation — happens only after some
  earlier, genuinely-valid chunks have already been written out. Writing directly to the
  user's requested output path would leave a truncated, unusable file sitting there on
  failure. `AtomicOutputFile` instead writes to a `<output>.pgotmp` sibling file and only
  renames it over the real destination once the whole operation succeeds
  (`std::filesystem::rename`, falling back to `copy_file` + `remove` if the rename fails,
  e.g. across a filesystem boundary — see [§11](#11-cross-platform-considerations)); its
  destructor removes the temp file on any unwind path where `commit()` was never called,
  mirroring the same "tie cleanup to scope exit, not to a manually-placed line before
  every return" reasoning as `ScopedZero` ([§5.7](#57-memory-hygiene-scopedzero--scopedzerostring)).
  This restores, at the level of "what ends up at `-output`," the same all-or-nothing
  guarantee the original whole-buffer design got for free by construction.
- **Compatibility constraint this introduces.** `kChunkSize` is compiled into the binary
  and not recorded anywhere in the payload (see [§5.5](#55-on-disk-payload-format)).
  `decryptStream`'s fixed-size reads only land on the correct chunk boundaries if the
  build decrypting a file uses the same `kChunkSize` the build that encrypted it did —
  see [§12](#12-known-limitations-and-trade-offs) for what happens if that constant ever
  changes across versions, and [§13](#13-future-directions) for how this could be made
  self-describing in the future.

## 6. Password acquisition design

### 6.1 Why not a CLI literal

`CommandLineOptions` has no `-password=` option, on purpose. Command-line arguments are
visible to every other process on the same machine via `ps`/`/proc/<pid>/cmdline`, and
are persisted in shell history files by default. A tool whose entire job is keeping a
file secret would undermine itself by accepting the secret through the one input channel
that's the least private. Every supported way of supplying a password
(interactive prompt, `-passwordfile`) avoids ever placing the literal password bytes on
the command line.

### 6.2 Interactive prompt and echo suppression

`promptForPassword` reads a line from `std::cin` while `ScopedEchoDisabled` (implemented
per-platform via Windows console mode flags or POSIX `termios`) suppresses terminal echo,
mirroring the UX of `sudo`/`ssh`/`passwd`. It falls back gracefully when stdin isn't a
TTY (piped input in scripts/tests) since disabling echo on a non-terminal stream is
simply a no-op rather than an error — this keeps the same code path usable both
interactively and from automation without a separate flag to say "don't try to touch the
terminal."

### 6.3 Password-file slicing (offset/length) rationale

`-passwordfile`/`-passwordoffset`/`-passwordlength` let the password be an arbitrary byte
range sliced out of an existing file, rather than requiring the file's _entire_ contents
to be the password. As the User Guide's
["Why use a password file"](UserGuide.md#why-use-a-password-file) section describes, this
turns "remember a password" into "remember which file, and which slice of it" — the
slice parameters (offset/length) act as a second factor that must also be reproduced to
decrypt, without Pgo needing any concept of multi-factor authentication itself. This is
also what makes the design suitable for scripted/automated use: a fixed offset/length
against a checked-in reference file is a reproducible, non-interactive password source,
whereas requiring the interactive prompt would block automation entirely.

The validation in `extractPasswordFromFile` (offset must not exceed file size,
offset+length must not exceed file size) exists so that a mistyped offset fails loudly
with a specific message rather than silently reading fewer bytes than intended (which
would silently change the effective password without any indication that it happened —
exactly the kind of silent behavior change that would turn "I forgot how many bytes I
meant to use" into "I can never decrypt this file again").

## 7. Command-line interface design

### 7.1 Dual argument syntax

Every option accepts both `-key value` and `-key=value` (see `parseCommandLine`). This
follows two different real-world conventions users are likely to already know (Windows
tools historically favor space-separated switches; Unix tools commonly use `=`), so
`PgoCli` doesn't force users into an unfamiliar convention as a precondition for using it
at all. Supporting both was cheap to implement (one branch on argument shape) relative to
picking one and fielding "why doesn't `-key value` work" questions forever.

### 7.2 Last-occurrence-wins semantics

If an option is repeated, `parseCommandLine` keeps overwriting `CommandLineOptions`
fields as it walks the token list, so the last occurrence silently wins. This specific
behavior is what makes [`-argfile`](#74-argument-files--argfile-and-the-cmdlinetxt-debug-convenience)
useful as a _base_ configuration: a user can put common defaults in an arg file and
override just one or two of them with real command-line arguments placed after the
`-argfile` token, without needing a separate "override" syntax — plain repetition already
does the job because of how expansion + parsing order is defined (see 7.4).

### 7.3 Non-fatal validation / continuation philosophy

An unrecognized `-key=value`, or a malformed token, is logged to `stderr` and skipped —
parsing continues rather than aborting on the first problem. The alternative (abort
immediately) would mean a single typo'd option hides whatever the _next_ problem would
have been, forcing a user to fix issues one at a time across multiple runs. Continuing
lets `main()`'s later, more specific validation (required-fields check, mode check,
input≠output check) surface the most actionable error given everything that was actually
parseable, while `stderr` still records every individual thing that looked wrong.

### 7.4 Argument files (`-argfile`) and the `CmdLine.txt` debug convenience

`-argfile[=path]` splices whitespace-separated tokens from a file into the argument list
at the position `-argfile` appeared, preserving order — real arguments before it stay
before, real arguments after it stay after (and, by 7.2's rule, can override anything
from the file). This turns any command line into something reusable/checked-in (see the
User Guide's [example](UserGuide.md#argument-files--argfile)) without inventing a config
file format — it's the same token grammar the CLI already parses, just sourced from a
file instead of `argv`.

The **Debug-only** auto-load of `CmdLine.txt` when `-argfile` wasn't passed at all exists
purely to make F5-debugging convenient (a debugger launch config doesn't need arguments
typed in for every run). It is deliberately **not** present in Release builds
(`#if defined(_DEBUG) || !defined(NDEBUG)`), because silently changing a _production_
tool's behavior based on which files happen to sit in the current directory is exactly
the kind of surprising, hard-to-audit behavior a shipped CLI should never have — a
Release binary's behavior should be fully determined by the arguments it was actually
given. Confining the convenience to Debug builds keeps it available where it's useful
(local development/debugging) without it ever being a behavior a Release-build user needs
to know about or defend against.

## 8. Error handling philosophy

Both `obfuscateFile` and `reverseFile` wrap their entire body in one `try`/`catch`, and
every internal failure — I/O errors, `sodium_init` failure, Argon2id failure, a
too-small payload, a failed AEAD tag check — is expressed as a thrown
`std::runtime_error` internally, caught once, and turned into `(false, error message)`.
`main()` follows the identical shape: everything that can go wrong throws
`std::invalid_argument`, caught once at the bottom of `main()`.

**Why a single catch site instead of per-call error checking:** with a single boolean/
string return contract, every caller (today: `PgoCli`; potentially in the future,
`PgoEngineTests` or another program entirely) only ever needs to check one `if` and read
one string, regardless of which of the several possible internal failures actually
occurred. Threading a distinct error code or exception type through every intermediate
helper (`readSalt`, `deriveKey`, `decryptStream`, ...) would multiply the number of
things a caller needs to know how to handle, for no benefit to a tool whose entire
external contract is "did this file operation succeed, and if not, why."

**Interaction with streamed output:** a single catch site handles *when* a caller learns
about a failure, but streaming (see [§5.9](#59-streaming-and-chunk-framing)) changes
what state exists on disk *before* that failure is reported — chunks may already be
written to the in-progress output by the time a later chunk fails. `AtomicOutputFile`
keeps this from being externally visible: it holds the in-progress write in a temp file
and only exposes it at `-output` via a rename on success, so from the caller's point of
view the contract stays exactly what it was under the original whole-buffer design —
either `-output` ends up with the complete, correct result, or it isn't touched at all.

## 9. Build system design

### 9.1 CMake + vcpkg manifest mode

Dependencies (`libsodium`, `gtest`) are declared in `vcpkg.json`, and vcpkg is vendored
directly inside the repository (`vcpkg/`) rather than assumed to be preinstalled on the
build machine. This means `cmake -S . -B build/... -DCMAKE_TOOLCHAIN_FILE=vcpkg/...`
triggers vcpkg to build exactly the dependency versions the manifest pins, on first
configure, with no separate "go install these libraries system-wide first" step and no
version drift between machines (or between a developer's machine and CI). Vendoring
vcpkg itself (rather than requiring it to be installed separately) means a fresh clone of
this repository is sufficient to build it, modulo the one-time
`bootstrap-vcpkg` step documented in [BUILD.md](../BUILD.md).

### 9.2 Static libraries and target boundaries

`PgoEngine`, `PgoCliLib`, `PgoEngineTests`, and `PgoCliTests` are each their own CMake
target with `target_include_directories(... PUBLIC Include)` on the two libraries. Static
linking (rather than shared/dynamic libraries) was chosen because Pgo ships as a single
CLI tool with no plugin architecture and no desire to manage runtime library search paths
across two OSes — a static binary is simpler to distribute and run than one with a
sibling `.dll`/`.dylib`/`.so` that has to be found at load time.

### 9.3 Compiler/linker hardening flags

The root `CMakeLists.txt` applies stack-smashing protection
(`-fstack-protector-strong`/`_FORTIFY_SOURCE=2` on non-MSVC, `/sdl`/`/guard:cf` +
`/GUARD:CF` on MSVC), position-independent execution and full RELRO on Linux, and
`/DYNAMICBASE`/`/NXCOMPAT` on Windows — **Release builds only**. This is standard
defense-in-depth for a tool whose entire job is handling untrusted-shaped input (a
`reverse`d file could be attacker-controlled, per the threat model in
[§5.1](#51-threat-model)) — these flags don't prevent a memory-safety bug from existing,
but they make one meaningfully harder to turn into working exploitation if one ever
slips through. They're scoped to Release only because a Debug build's entire purpose is
being easy to step through in a debugger; paying for stack canaries and fortified libc
calls while single-stepping provides no value and would only slow down the inner loop of
development.

### 9.4 Debug vs Release cost parameters

`main.cpp` sets `EngineConfig::tCost = 2, mCost = 1u << 16` (64 MiB) in Debug and
`tCost = 4, mCost = 1u << 18` (256 MiB) in Release, guarded by the same
`_DEBUG`/`NDEBUG` check used elsewhere. The Release values are what actually protects
users' files (see [§5.3](#53-key-derivation-argon2id)); the lower Debug values exist
purely so that manually running/debugging `PgoCli` during development isn't slowed down
by the full production Argon2id cost on every single test invocation. This is distinct
from — and _not_ a substitute for — the test suite's own even-lower cost parameters (see
[§10.3](#103-test-isolation-temp-directories-and-fast-kdf-parameters)), which exist for
the same reason taken further: automated tests run far more often than a human manually
re-running the CLI, so they use libsodium's actual documented _minimum_ accepted cost
parameters rather than merely a reduced one.

## 10. Testability design

### 10.1 Why `CommandLine.*` was extracted from `main.cpp`

Covered in depth in [§4.2](#42-pgoclilib) — the short version is that an anonymous
namespace inside `main.cpp` is invisible outside that translation unit, so there was no
way to unit-test argument parsing without either linking a second `main()` into the test
binary or duplicating the logic somewhere the test could reach it (which would test a
copy, not the real code path `PgoCli` actually runs). Extracting the pure-logic functions
into their own header/`.cpp` pair, exposed via the `PgoCliLib` target, let the test binary
link the _exact_ production code with no `main()` symbol collision.

### 10.2 GoogleTest integration and two test binaries, not one

`Tests/CMakeLists.txt` calls `find_package(GTest CONFIG REQUIRED)` once and then
`add_subdirectory`s two independent test executables, `PgoEngineTests` (linking
`PgoEngine` + `GTest::gtest_main`) and `PgoCliTests` (linking `PgoCliLib` +
`GTest::gtest_main`), each discovered via `gtest_discover_tests` so `ctest` sees every
`TEST`/`TEST_F` as its own individually reportable test case.

**Why two binaries instead of one combined test executable:** the two libraries under
test have no dependency on each other (`PgoCliLib` doesn't link `PgoEngine`, and vice
versa) — combining their tests into a single binary would create a build dependency
between two things that are architecturally independent, purely for test-running
convenience, and would make it slightly slower to iterate on one library's tests without
recompiling anything related to the other. Separate binaries mirror the separate
production library boundary described in [§4](#4-component-architecture) exactly.

### 10.3 Test isolation (temp directories and fast KDF parameters)

Every `PgoEngineTest`/`ExtractPasswordFromFileTest`/`ExpandArgsTest` fixture creates a
uniquely-named subdirectory under `::testing::TempDir()` (namespaced by test suite and
test name) in `SetUp()` and removes it in `TearDown()`, rather than writing fixture files
into the repository or a single shared scratch directory. This is what allows the full
suite to run safely in parallel or in any order: no test can observe a file left behind
by another test, or race another test writing to the same path, and a crashed/aborted
run doesn't leave stale fixtures for the next run to trip over (`SetUp` also proactively
`remove_all`s the target directory before creating it, in case a previous run left it
behind uncleanly).

`PgoEngineTests` uses `tCost = 1, mCost = 8` (8 KiB — libsodium's documented
`crypto_pwhash_argon2id` minimum) instead of the CLI's real cost parameters
([§9.4](#94-debug-vs-release-cost-parameters)), since the tests are verifying
_correctness_ of the encrypt/decrypt round trip and its failure modes, not exercising
Argon2id's actual guessing-resistance — running the full production cost parameters on
every test invocation would make the suite meaningfully slower for no gain in what it
actually verifies.

`ExpandArgsTest` additionally `chdir`s into its own temp directory for the duration of
each test (restoring the original working directory in `TearDown`), specifically because
`expandArgs`'s Debug-build convenience behavior
([§7.4](#74-argument-files--argfile-and-the-cmdlinetxt-debug-convenience)) reads
`CmdLine.txt` from the _current_ directory — and this repository has a real
`CmdLine.txt` checked in at the repo root for manual testing. Without isolating the
working directory, a Debug-configured test run could silently pick up the repository's
own `CmdLine.txt` and produce a result that depends on a file the test never mentioned,
which is precisely the kind of hidden coupling test isolation exists to prevent.

### 10.4 Exercising chunk boundaries

Most `PgoEngineTest` cases use short, single-chunk strings, since they're targeted at a
specific failure mode (wrong password, one tampered byte, a handful of truncated bytes)
rather than at the chunking mechanism itself. A separate handful of tests
(`RoundTripHandlesMultiChunkFile`,
`ReverseFailsWhenMultiChunkPayloadIsMissingItsFinalChunk`,
`ReverseFailsWhenAnEarlyChunkOfMultiChunkPayloadIsTampered`,
`ReverseFailsWhenDataFollowsTheFinalChunk`) instead build multi-megabyte content,
specifically to drive `encryptStream`/`decryptStream` through more than one chunk —
otherwise the single-chunk tests above would pass even if chunk-boundary handling
(where the `TAG_FINAL` chunk actually lands, whether an early, non-final chunk is
authenticated at all) were silently broken. These use a multi-megabyte size rather than
a size expressed in terms of `kChunkSize` directly, since that constant is an
implementation detail of `PgoEngine.cpp` the tests (which only see the public
`PgoEngine.h` API) have no access to and shouldn't need to hardcode.

## 11. Cross-platform considerations

- **Terminal echo suppression** (`ScopedEchoDisabled`) has entirely separate
  implementations for Windows (`GetConsoleMode`/`SetConsoleMode`) and POSIX
  (`tcgetattr`/`tcsetattr`), selected via `#ifdef _WIN32`, since there is no portable
  standard-library API for this — it is inherently an OS console/terminal concept.
- **Hardening flags** differ by toolchain (MSVC flags vs. GCC/Clang flags,
  [§9.3](#93-compilerlinker-hardening-flags)), and PIE/RELRO linker flags are further
  scoped to `CMAKE_SYSTEM_NAME STREQUAL "Linux"` specifically, since Mach-O (macOS) is
  PIE by default and doesn't use the same linker syntax, and the Windows equivalents are
  already handled in the MSVC branch.
- **Build generator**: Windows builds add `-G "NMake Makefiles"` (see `tasks.json`/
  `BUILD.md`) so the output layout is single-config like Mac/Linux's default Makefiles
  generator, rather than defaulting to a multi-config Visual Studio generator — this
  keeps the `build/<debug|release>/...` output layout identical across all three
  platforms, which is what lets `BUILD.md` document one set of paths instead of
  per-platform variants.
- **`AtomicOutputFile`'s rename** (see [§5.9](#59-streaming-and-chunk-framing)) uses
  `std::filesystem::rename`, which is atomic on POSIX when source and destination are on
  the same filesystem, and is backed by `MoveFileEx` on Windows (similarly atomic
  same-volume). Both platforms can fail that rename when `-output` is on a different
  filesystem/volume than the temp file (created alongside `-output`, so this is only
  possible if `-output`'s directory itself is a mount point), in which case
  `AtomicOutputFile` falls back to `copy_file` + `remove` — which is **not** atomic, so a
  crash mid-fallback could in principle leave a fully-written `-output` and a
  not-yet-removed temp file, though the common same-filesystem case never takes this path
  at all.

## 12. Known limitations and trade-offs

These are conscious, not oversights — recorded here so a future change is made with the
original trade-off in view rather than rediscovering it the hard way:

- **Chunk size is a compile-time constant, not stored on disk.** As explained in
  [§5.9](#59-streaming-and-chunk-framing), `decryptStream` derives its read-chunk size
  from `kChunkSize` in the binary doing the decrypting, not from anything recorded in the
  payload. If a future version of Pgo changed `kChunkSize`, files obfuscated by an older
  (or newer) build would no longer decrypt correctly with the changed build — every
  `crypto_secretstream_..._pull` call would be fed the wrong-length ciphertext for its
  frame and fail authentication, so this fails safely (as "integrity check failed" or a
  truncation error) rather than silently misdecoding, but it would still make previously
  valid files unreadable. This has not been a problem in practice since `kChunkSize` has
  only ever had the one value, but it is the trade-off accepted in exchange for not
  needing to store and validate a chunk-size field in every payload.
- **Fixed Argon2id cost parameters.** As discussed in [§5.3](#53-key-derivation-argon2id),
  configurable cost parameters would need to be stored in the payload (like the salt
  already is) to avoid users locking themselves out of their own files — that plumbing
  doesn't exist yet, so cost parameters remain a compile-time constant tied to build
  configuration.
- **No key-rotation/multi-recipient story.** A file is bound to exactly one password.
  Sharing an obfuscated file with multiple people who should each use their own password,
  or rotating a password without re-encrypting the whole file, are both unsupported —
  intentionally, per the non-goals in [§2](#2-goals-and-non-goals).
- **Wrong password vs. corrupted file are indistinguishable**, by design
  ([§5.8](#58-failure-semantics-fail-closed-authentication)) — this is a limitation from
  a "helpful error message" standpoint even though it's the _correct_ cryptographic
  behavior.
- **Non-atomic fallback path for cross-filesystem output**, described in
  [§11](#11-cross-platform-considerations) — accepted because it only triggers when
  `-output` resolves to a different filesystem/volume than its own directory, an
  unusual setup for this tool's typical usage.

## 13. Future directions

Ideas that would fit naturally into the existing architecture, should the goals in
[§2](#2-goals-and-non-goals) ever expand:

- **Per-file cost parameters:** extend the on-disk payload
  ([§5.5](#55-on-disk-payload-format)) to store `tCost`/`mCost` alongside the salt, then
  expose `-tcost`/`-mcost` CLI options in `PgoCliLib`'s parser, so cost can be tuned per
  invocation without any risk of a file becoming unreadable (the parameters used to
  create it would always travel with it).
- **Self-describing chunk size:** store `kChunkSize` itself alongside the salt and stream
  header ([§5.5](#55-on-disk-payload-format)), the same way per-file cost parameters
  above would be — this would let `decryptStream` read whatever chunk size a given file
  was actually written with, removing the cross-version compatibility constraint noted in
  [§12](#12-known-limitations-and-trade-offs) entirely, at the cost of one more field to
  parse and validate up front.
- **A library-only consumption path:** since `PgoEngine` already has no CLI-specific
  concepts baked into it ([§4.1](#41-pgoengine)), a second front end (GUI, batch/
  scripting API) could link it directly today without any changes to `PgoEngine` itself.
