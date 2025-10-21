# PrefetchView++

**PrefetchView++** is a tool for analyzing Windows Prefetch files, providing detailed information about file paths, digital signatures, and referenced files, all within a modern ImGui-based interface.

---

## Features

- **Prefetch Analysis**: Parses Prefetch files from the system, extracting information about each execution.
- **Path Conversion**: Converts Windows device paths (`\Volume\{xx-xx-xx}`) to standard paths (`C:\`), making the results easier to read.
- **Digital Signature Verification**: Identifies whether executables are signed, unsigned, or not found.
- **Modern ImGui Interface**:
  - Main table displaying paths and signatures.
  - Search bar for filtering results.
  - Click on rows to view additional details.
  - Right-click options to copy or open any file path.