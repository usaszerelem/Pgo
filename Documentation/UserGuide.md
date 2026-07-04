# Pretty Good Obfuscation (Pgo) User Guide

Pgo is a password-based file obfuscation/encryption tool. It takes any file, derives an encryption
key from a password you supply, and produces an encrypted copy that can only be read back
(reversed) by someone who knows that same password. It ships as two pieces:

- **PgoEngine** — the core library that implements encryption/decryption.
- **PgoCli** — the command-line program you actually run; it is a thin front end over
  PgoEngine.

This guide covers how to use `PgoCli`. For build/compilation instructions, see
[BUILD.md](../BUILD.md).

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Command-line reference](#command-line-reference)
- [Providing the password](#providing-the-password)
- [Argument files (`-argfile`)](#argument-files--argfile)
- [Examples](#examples)
- [Error handling and exit codes](#error-handling-and-exit-codes)
- [Security considerations](#security-considerations)
- [Automated tests](#automated-tests)
- [Troubleshooting / FAQ](#troubleshooting--faq)

## How it works

Every file Pgo produces (an "obfuscated" file) has the following layout:

```
[ salt (16 bytes) | stream header (24 bytes) | chunk 1 | chunk 2 | ... | final chunk ]
```

- **Key derivation**: your password and a freshly generated random **salt** are fed into
  **Argon2id** (via libsodium's `crypto_pwhash`), a memory-hard key derivation function.
  This makes offline password-guessing attacks against a stolen file expensive, since each
  guess costs the attacker the same time/memory budget it costs you.
- **Encryption**: the derived key initializes an authenticated **XChaCha20-Poly1305
  stream** (libsodium's `crypto_secretstream` API). The file is read and encrypted in
  fixed-size chunks (64 KiB) rather than all at once, so Pgo's memory use stays roughly
  constant no matter how large the input file is — obfuscating a 1 KB file and a 10 GB
  file both use about the same amount of memory.
- **Every chunk is authenticated, including which one is last.** This means `reverse`
  detects not just a wrong password or a tampered byte anywhere in the file, but also a
  file that was truncated (an interrupted copy or upload that dropped the end of the
  file) or that has extra bytes appended after the real end.
- **Salt and stream header are not secret** — they're stored in plain sight at the start
  of the output file. `reverse` mode reads them back out to re-derive the same key and
  re-initialize the same stream. Because both are freshly randomized on every run,
  obfuscating the same file twice with the same password produces two different,
  unrelated-looking outputs.
- **Wrong password, or a tampered/truncated file → clean failure.** Because every chunk
  is authenticated, decrypting with the wrong password (or a file that was modified,
  truncated, or extended after being obfuscated) doesn't produce garbage or partial
  output — it fails outright with an error, and no partially-written file is left behind
  at the requested output path (Pgo writes to a temporary file first and only replaces
  the destination once the whole operation succeeds).

## Quick start

Encrypt (`obfuscate`) a file, then decrypt (`reverse`) it back:

```
PgoCli -mode=obfuscate -input=notes.txt -output=notes.pgo
PgoCli -mode=reverse   -input=notes.pgo -output=notes.txt
```

With no `-passwordfile` given, you'll be prompted to type a password (input is not echoed
to the terminal). Use the **same password** for both commands.

## Command-line reference

```
PgoCli -mode=<obfuscate|reverse> -input=<path> -output=<path>
       [-passwordfile=<path> [-passwordoffset=N] [-passwordlength=N]]
       [-argfile[=path]] [-help]
```

| Option            | Required? | Description                                                                                                  |
| ----------------- | --------- | ------------------------------------------------------------------------------------------------------------ |
| `-mode`           | Yes       | `obfuscate` (encrypt) or `reverse` (decrypt). Case-insensitive.                                              |
| `-input`          | Yes       | Path to the file to read (plaintext for `obfuscate`, a previously obfuscated file for `reverse`).            |
| `-output`         | Yes       | Path to write the result to. Overwritten if it already exists. Must differ from `-input`.                    |
| `-passwordfile`   | No        | Extract the password as raw bytes from this file instead of prompting interactively.                         |
| `-passwordoffset` | No        | Byte offset into `-passwordfile` to start reading the password from. Default `0`.                            |
| `-passwordlength` | No        | Number of bytes to read from `-passwordfile`. Default: read to the end of the file.                          |
| `-argfile[=path]` | No        | Load additional arguments from a file. Default path is `CmdLine.txt`. See [below](#argument-files--argfile). |
| `-help`           | No        | Print usage and exit immediately (ignores every other argument).                                             |

### Two argument syntaxes

Every option (except `-help` and bare `-argfile`) accepts either form, and they can be
freely mixed on the same command line:

```
-mode=obfuscate          # single-token "-key=value" form
-mode obfuscate           # two-token "-key value" form
```

If an option is given more than once, **the last occurrence wins**.

Anything that isn't recognized (an unknown `-key=value`, or a token that isn't a valid
`-key=value` or one of the two-token options above) is reported to stderr and skipped —
it does not stop the program, so a single typo won't necessarily hide a different, more
specific validation error further along.

## Providing the password

The password is **never** accepted as a literal value on the command line — typing it as
plain text would leak it into your shell history and to anyone who runs `ps` while the
process is running. Instead, choose one of:

1. **Interactive prompt (default)** — if `-passwordfile` is not given, you'll see a
   `Password:` prompt and your input will not be echoed to the screen.
2. **Password file** — supply `-passwordfile=<path>`, and optionally `-passwordoffset`
   and `-passwordlength`, to use raw bytes sliced out of an existing file as the password.
   This is useful for scripting/automation where an interactive prompt isn't practical.
   - Without `-passwordlength`, Pgo reads from `-passwordoffset` to the end of the file.
   - The offset must not be past the end of the file, and offset+length must not exceed
     the file's size — otherwise Pgo reports an error and exits without doing anything.

## Why use a password file

Using a password file can be beneficial in several ways. This file can be
any large text file, such as the US Constitution, and you specify what text portion
within this file should be the password by specifying also a offset and a length.

The recipient who reverses the encryption would need to know this same information in
order to decrypt the file. This method makes it very hard, if near impossible for any
other person to decrypt the payload.

Also worth noting that the payload itself can be encrypted in a different way (double
encrypted), that poses another layer of difficulty for somebody to decrypt the payload.

Password material (whether typed or extracted from a file) is scrubbed from memory as
soon as it's no longer needed, rather than left to linger in freed heap memory.

## Argument files (`-argfile`)

`-argfile` lets you keep a command's arguments in a text file instead of retyping them,
and works two ways:

- **`-argfile=path/to/file`** — reads whitespace-separated tokens from that file and
  splices them into the argument list at that position, in order. Real command-line
  arguments elsewhere on the invocation still apply normally (and, per the "last wins"
  rule above, override anything conflicting from the arg file if they appear later).
- **`-argfile`** (no path) — same, but reads from the default path, `CmdLine.txt` in the
  current directory.

Example `CmdLine.txt`:

```
-mode=reverse
-input=./Test/Sample.dat
-output=./Test/Sample2.txt
```

```
PgoCli -argfile
```

> **Debug-build convenience:** in Debug builds only, if you don't pass `-argfile` at all,
> Pgo will silently look for `CmdLine.txt` in the current directory and load it anyway
> (real arguments you do type still take precedence). This exists purely so a debugger
> launch config doesn't need arguments typed in every time. Release builds never do this
> — if you rely on `CmdLine.txt`, pass `-argfile` explicitly.

## Examples

**Obfuscate a file, prompting for the password:**

```
PgoCli -mode=obfuscate -input=./Test/Sample.txt -output=./Test/Sample.dat
```

**Reverse it back:**

```
PgoCli -mode=reverse -input=./Test/Sample.dat -output=./Test/Sample2.txt
```

**Obfuscate using a slice of another file as the password** (bytes 100-109 of
`Bible.txt`), avoiding any interactive prompt:

```
PgoCli -mode=obfuscate -input=./Test/Sample.txt -output=./Test/Sample.dat \
       -passwordfile=./Test/Bible.txt -passwordoffset=100 -passwordlength=10
```

**Reverse using the same password-file slice:**

```
PgoCli -mode=reverse -input=./Test/Sample.dat -output=./Test/Sample2.txt \
       -passwordfile=./Test/Bible.txt -passwordoffset=100 -passwordlength=10
```

**Load all arguments from a file:**

```
PgoCli -argfile=./CmdLine.txt
```

## Error handling and exit codes

- **Exit code `0`** — success (or `-help`, which prints usage and exits immediately).
- **Exit code `1`** — any failure: missing required options, an empty password, an
  input/output path problem, or a PgoEngine failure (wrong password, corrupted/tampered
  file, unreadable input, etc.). Usage help and the specific error message are printed to
  the console.

Common failure messages and what they mean:

| Message (paraphrased)                                             | Cause                                                                            |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| "Input, output, and mode are required."                           | One of `-input`/`-output`/`-mode` was missing.                                   |
| "Password must not be empty."                                     | You hit Enter at the password prompt without typing anything.                    |
| "Extracted password from -passwordfile is empty."                 | `-passwordlength` (or the remaining file) resolved to zero bytes.                |
| "Password offset is beyond the end of file: ..."                  | `-passwordoffset` is larger than the password file itself.                       |
| "Password file is too short for the requested offset/length: ..." | `-passwordoffset` + `-passwordlength` exceeds the file's size.                   |
| "Mode must be either 'obfuscate' or 'reverse'."                   | `-mode` was something else.                                                      |
| "Input and output paths must be different."                       | `-input` and `-output` pointed at the same path.                                 |
| "unable to open input file"                                       | The obfuscate/reverse input path doesn't exist or isn't readable.                |
| "unable to create output file" / "unable to write to output file" | Pgo couldn't create its temporary output file or finalize it at `-output` (e.g. the destination directory doesn't exist or isn't writable). |
| "integrity check failed"                                          | Wrong password, or a chunk of the input file was corrupted/tampered with, during `reverse`. |
| "payload too small for salt" / "payload too small for stream header" | The `reverse` input is not (or is no longer) a valid Pgo-obfuscated file.     |
| "truncated payload: missing final chunk"                          | The `reverse` input ends before reaching the chunk marked as the last one — the file was cut short. |
| "unexpected trailing data after final chunk"                      | Extra bytes follow the legitimate end of the encrypted stream — something was appended to the file after it was obfuscated. |

## Security considerations

- Pgo streams files through encryption/decryption in fixed-size (64 KiB) chunks rather
  than reading them fully into memory, so there's no practical file-size limit imposed by
  available RAM. This chunk size is fixed at build time and not recorded in the
  obfuscated file itself, so a file should be reversed with a compatible build of Pgo —
  in practice this only matters if you keep obfuscated files around across major Pgo
  upgrades.
- Argon2id cost parameters are lower in Debug builds (faster, for development) and higher
  in Release builds (slower, more resistant to offline guessing). You cannot currently
  configure these from the command line.
- A wrong password and a corrupted file produce the **same kind of error** ("integrity
  check failed") — Pgo cannot and does not distinguish between the two, by design.
- Deleting the plaintext after obfuscating it does not itself guarantee the data is
  unrecoverable from disk (that depends on your filesystem/storage medium); Pgo only
  guarantees the _obfuscated_ output can't be read without the password.
- Keep your password (or password-file/offset/length combination) somewhere durable and
  memorable — there is no recovery mechanism if you lose it. A forgotten password makes
  an obfuscated file permanently unreadable.

## Automated tests

The project ships GoogleTest-based automated tests covering both `PgoEngine` (encryption
round-trips, wrong-password/tampered/truncated-file handling) and `PgoCli`'s
argument-parsing logic. They aren't required to use `PgoCli`, but if you're building from
source:

```
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

See [BUILD.md](../BUILD.md#running-tests) for details.

## Troubleshooting / FAQ

**I forgot to give `-mode`/`-input`/`-output` — why does it print usage AND an error?**
Both are intentional: usage is a reminder of the full syntax, and the line below it is the
specific reason this particular invocation failed.

**Can I put the password directly on the command line?**
No — this is deliberate, so it doesn't end up in your shell history or a process listing.
Use `-passwordfile` or the interactive prompt instead.

**Why did my `-argfile`-less invocation pick up options I didn't type?**
You're likely running a Debug build with a `CmdLine.txt` sitting in your current
directory — see the callout in [Argument files](#argument-files--argfile).

**I ran `reverse` and got "integrity check failed" — is my file corrupted?**
Not necessarily — this is also what you get from simply using the wrong password. Double
check the password (and, if using `-passwordfile`, the exact offset/length) before
assuming the file itself is damaged.
