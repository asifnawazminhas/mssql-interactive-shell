# mssql-interactive-shell

Interactive MSSQL `xp_cmdshell` console with file upload support, autocomplete, command history, and remote command execution.  
Designed for ethical security testing, red team labs, and training scenarios.

---

## Features

- Interactive MSSQL shell using `xp_cmdshell`
- Full command execution (dir, whoami, systeminfo, etc.)
- Tab autocomplete for:
  - Common commands
  - Remote files and directories
  - Local files during upload
---

## Requirements

- Python 3.8+
- The following Python modules:
  - `tqdm`
  - `readline` (Linux/macOS)
  - `_mssql` or `pymssql`

## Install dependencies:

```bash
pip install pymssql tqdm
```

## Usage
```bash
python3 mssql_shell.py
```

## Once connected, the shell will look like:
```bash
CMD username@COMPUTERNAME C:\Users\Public>
```

## Run commands
```bash
CMD ...> whoami
CMD ...> dir
CMD ...> systeminfo
CMD ...> net user
```

