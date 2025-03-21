# 0ver - Forensic Disk Verification & Wiping Tool

<div align="center">
  <p><em>Pronounced "zero ver(ification)" or simply "Over"</em></p>

  ![0ver Banner](https://img.shields.io/badge/0ver-Forensic%20Disk%20Verification%20%26%20Wiping%20Tool-blue)
  [![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
  [![Release](https://img.shields.io/github/v/release/StefFriend/0ver?include_prereleases)](https://github.com/StefFriend/0ver/releases)
  </div>

## Overview

0ver is a powerful forensic utility designed for digital investigators, security professionals, and system administrators to verify and securely wipe hard drives. It scans storage devices at the sector level to detect non-zero data and provides the option to selectively zero out these sectors, ensuring complete data elimination for forensic purposes.

## Key Features

- **Thorough Sector-Level Scanning**: Identifies all non-zero sectors on physical drives
- **Multi-threaded Processing**: Leverages parallel processing for faster scanning of large drives
- **Detailed Logging**: Maintains comprehensive logs of all operations for chain of custody documentation
- **Selective Wiping**: Option to zero out only sectors containing data rather than entire drives
- **Progress Tracking**: Real-time scanning and wiping progress with ETA
- **Multilingual Support**: Available in English and Italian
- **Administrator-Friendly**: Clear warnings and guidance for safe operation

## System Requirements

- Windows operating system (Windows 7/8/10/11)
- Administrative privileges
- Python 3.6 or higher
- Sufficient disk space for log files

## Installation

### Option 1: Standalone Executable

For users who prefer not to install Python or dependencies, we provide a standalone executable:

1. Navigate to the [Releases](https://github.com/yourusername/0ver/releases) page
2. Download the latest `0ver-vX.X.X.exe` file
3. Run with administrator privileges

The executable version has the following benefits:
- No Python installation required
- All dependencies bundled
- Potentially faster execution
- Compatible with Windows 7/8/10/11 (both 32-bit and 64-bit)

### Option 2: Python Script

If you prefer to run the Python script directly:

#### Prerequisites

Ensure you have Python 3.6+ and pip installed on your system.

#### Required Packages

```bash
pip install tqdm wmi ctypes
```

#### Download

```bash
git clone https://github.com/yourusername/0ver.git
cd 0ver
```

## Usage

### Important Warning

⚠️ **CAUTION**: This tool directly accesses physical drives at the sector level. Improper use can result in permanent data loss. Always run 0ver on drives that you intend to wipe, never on drives containing data you wish to keep.

### Running the Tool

Run the script with administrative privileges:

```bash
# Right-click on PowerShell or Command Prompt and select "Run as Administrator"
cd path\to\0ver
python 0ver.py
```

### Operational Steps

1. Select your preferred language (English or Italian)
2. The tool will scan for available physical drives
3. Select the drive to verify
4. Choose a log file name or accept the default
5. Select log mode (detailed or summary)
6. Confirm to start the scanning process
7. After scanning completes, review findings and decide whether to zero out non-zero sectors

## Understanding the Results

- **Scan Results**: The tool identifies all sectors containing non-zero data
- **Log Files**: Detailed logs are created with information including:
  - Drive identification
  - Scan date/time
  - Sector size
  - List of non-zero sectors (in detailed mode)
  - Statistical summary
  - Wiping operations (if performed)

## Safety Considerations

- **Run in a Controlled Environment**: Never run on production systems unless you intend to wipe them
- **Verification**: Always verify drive selection before confirming operations
- **Backup**: Critical data should be backed up before using this tool
- **Legal Implications**: Ensure you have proper authorization to wipe the target drives
- **Chain of Custody**: For forensic purposes, maintain proper documentation of all operations

## Technical Details

0ver works directly with physical drives at the hardware level:

- Detects hardware sector size (typically 512 or 4096 bytes)
- Uses Windows API for direct drive access
- Performs optimized multi-threaded reading operations
- Employs buffered writes for efficient zeroing
- Handles interruptions gracefully with partial logging

## Contributing

Contributions to 0ver are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the GNU General Public License v3.0 (GNU GPLv3) - see the LICENSE file for details.

If you use this software please cite this repo: [0ver - Forensic Disk Verification & Wiping Tool (https://github.com/StefFriend/0ver)](https://github.com/StefFriend/0ver)

## Disclaimer

This software is provided "as is", without warranty of any kind. The authors are not responsible for any data loss or damage resulting from the use of this tool. Use at your own risk and only on systems you are authorized to access.
