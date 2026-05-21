# PrefetchView++

**PrefetchView++** is an advanced Windows Prefetch parser built for forensic analysis and threat hunting.  
It provides detailed insights into `.pf` files, including execution timestamps, imported files, executable metadata, file sizes, run counts, and more.

The project also includes:

* Digital signature verification
* Replace detection using the USN Journal
* YARA Rules integration
* Bypass detection
* SysMain service timing analysis

---

## Features

### Advanced Prefetch Parsing

* Parses Windows Prefetch files and extracts:

  * Execution timestamps
  * Imported files
  * Executable metadata
  * File sizes
  * Run counts

### Path Resolution

* Automatically converts `\\Volume-{GUID}\\` device paths into standard drive-letter paths (`C:\\`, `D:\\`, etc).

### Digital Signature Verification

* Verifies digital signatures for:

  * Main executable paths
  * Imported files found inside the Prefetch

* Detects:

  * Unsigned files
  * Fake signatures
  * Cheat-related signatures

### YARA Rules

* Includes Generic detections powered by YARA Rules.
* Clicking a Generic entry reveals the exact matched rule for easier investigation.

### Search

* Built-in search box with support for searching across:

  * Main Prefetch table
  * Imports table

> Makes finding suspicious entries way easier, ngl.

---

## Filters

### `Post Logon`

Shows all entries executed after the user's logon time.

### `Show Untrusted`

Displays entries flagged as:

* Unsigned
* Fake signed
* Cheat-related

### `Show Not Found`

Displays paths that couldn't be resolved or were missing from disk.

> Same filters work for imports too, btw.

---

## Buttons

### `Prefetch Report`

Shows possible bypasses such as:

* Registry Prefetch
* Same hash detections
* Suspended threats
* Other suspicious artefacts

### `Sysmain Status`

Displays:

* SysMain service uptime
* Restart time

### `USN Journal`

Checks whether Prefetch folders or files were:

* Deleted
* Renamed

---

The whole tool is built using Dear ImGui, making the UI clean, and much easier to understand.
