#!/usr/bin/env python3
import os
import sys
import time
import ctypes
from ctypes import windll, wintypes, byref, sizeof, Structure, c_ulonglong
import concurrent.futures
from tqdm import tqdm

# Global language setting (will be set at runtime)
LANGUAGE = "en"  # Default language

# Translation dictionary
TRANSLATIONS = {
    # General messages
    "windows_only": {
        "it": "Questo script è pensato per Windows (os.name != 'nt'). Interrompo.",
        "en": "This script is designed for Windows (os.name != 'nt'). Aborting."
    },
    "admin_warning": {
        "it": "ATTENZIONE: Lo script potrebbe non funzionare correttamente senza privilegi amministrativi.",
        "en": "WARNING: The script may not work correctly without administrative privileges."
    },
    "admin_suggestion": {
        "it": "Si consiglia di eseguire lo script come Amministratore.",
        "en": "It is recommended to run the script as Administrator."
    },
    "searching_drives": {
        "it": "Ricerca drive fisici in corso...",
        "en": "Searching for physical drives..."
    },
    "no_drives_found": {
        "it": "Non è stato possibile trovare alcun PhysicalDrive apribile. Assicurarsi di essere Admin.",
        "en": "No accessible PhysicalDrive was found. Make sure you are an Admin."
    },
    "inaccessible_drives": {
        "it": "Drive non accessibili o non leggibili:",
        "en": "Inaccessible or unreadable drives:"
    },
    "available_drives": {
        "it": "Drive fisici disponibili:",
        "en": "Available physical drives:"
    },
    "select_drive": {
        "it": "Seleziona il numero del drive [1..{0}]: ",
        "en": "Select drive number [1..{0}]: "
    },
    "invalid_choice": {
        "it": "Scelta non valida.",
        "en": "Invalid choice."
    },
    "enter_log_file": {
        "it": "Inserire il nome file di log (default: {0}): ",
        "en": "Enter log file name (default: {0}): "
    },
    "about_to_scan": {
        "it": "Stai per avviare la scansione di: {0} - {1}",
        "en": "You are about to scan: {0} - {1}"
    },
    "size": {
        "it": "Dimensione: {0}",
        "en": "Size: {0}"
    },
    "sector_size": {
        "it": "Dimensione settore: {0} byte",
        "en": "Sector size: {0} bytes"
    },
    "log_file_mode": {
        "it": "File di log: {0} (Modalità: {1})",
        "en": "Log file: {0} (Mode: {1})"
    },
    "start_scan": {
        "it": "Avviare la scansione? [s/n]: ",
        "en": "Start scanning? [y/n]: "
    },
    "operation_cancelled": {
        "it": "Operazione annullata.",
        "en": "Operation cancelled."
    },
    "no_zero_sectors": {
        "it": "Nessun settore non azzerato, nessuna scrittura necessaria.",
        "en": "No non-zero sectors found, no writing necessary."
    },
    "rewrite_sectors": {
        "it": "Vuoi riscrivere a zero i {0} settori trovati? [s/n]: ",
        "en": "Do you want to zero-out the {0} sectors found? [y/n]: "
    },
    "rewrite_cancelled": {
        "it": "Operazione di riscrittura annullata.",
        "en": "Rewrite operation cancelled."
    },
    "operation_interrupted": {
        "it": "Operazione interrotta dall'utente.",
        "en": "Operation interrupted by user."
    },
    "error_occurred": {
        "it": "Si è verificato un errore: {0}",
        "en": "An error occurred: {0}"
    },
    "program_terminated": {
        "it": "Programma terminato.",
        "en": "Program terminated."
    },
    "of_total": {
        "it": "del totale",
        "en": "of total"
    },
    
    # Log mode selection
    "choose_log_mode": {
        "it": "Scegli la modalità di log:",
        "en": "Choose log mode:"
    },
    "log_mode_detailed": {
        "it": "  1. Completo (registra tutti i settori non-zero)",
        "en": "  1. Detailed (logs all non-zero sectors)"
    },
    "log_mode_summary": {
        "it": "  2. Riassuntivo (registra solo statistiche generali)",
        "en": "  2. Summary (logs only general statistics)"
    },
    "select_log_mode": {
        "it": "Seleziona la modalità [1/2]: ",
        "en": "Select mode [1/2]: "
    },
    "log_mode_detailed_name": {
        "it": "completo",
        "en": "detailed"
    },
    "log_mode_summary_name": {
        "it": "riassuntivo",
        "en": "summary"
    },
    
    # Scanning messages
    "scanning_drive": {
        "it": "Scansione di {0} in corso...",
        "en": "Scanning {0}..."
    },
    "disk_size": {
        "it": "Dimensione disco: {0}",
        "en": "Disk size: {0}"
    },
    "disk_size_unknown": {
        "it": "Dimensione disco: Sconosciuta",
        "en": "Disk size: Unknown"
    },
    "log_file": {
        "it": "File di log: {0}",
        "en": "Log file: {0}"
    },
    "using_workers": {
        "it": "Utilizzo {0} thread worker",
        "en": "Using {0} worker threads"
    },
    "press_ctrl_c": {
        "it": "Per interrompere la scansione, premi Ctrl+C",
        "en": "To interrupt the scan, press Ctrl+C"
    },
    "scan_interrupted": {
        "it": "Scansione interrotta dall'utente (Ctrl+C).",
        "en": "Scan interrupted by user (Ctrl+C)."
    },
    "sectors_found_so_far": {
        "it": "Settori non azzerati trovati finora: {0}",
        "en": "Non-zero sectors found so far: {0}"
    },
    "partial_results_saved": {
        "it": "I risultati parziali sono stati salvati nel file di log.",
        "en": "Partial results have been saved to the log file."
    },
    "scan_completed": {
        "it": "Scansione terminata in {0:.1f} secondi.",
        "en": "Scan completed in {0:.1f} seconds."
    },
    "total_bytes_processed": {
        "it": "Byte totali elaborati: {0}",
        "en": "Total bytes processed: {0}"
    },
    "error_chunks_warning": {
        "it": "Attenzione: {0} chunk ({1}) non sono stati letti a causa di errori.",
        "en": "Warning: {0} chunks ({1}) could not be read due to errors."
    },
    "found_nonzero_sectors": {
        "it": "Trovati {0} settori non azzerati.",
        "en": "Found {0} non-zero sectors."
    },
    "all_sectors_zero": {
        "it": "Tutti i settori esaminati risultano a zero.",
        "en": "All examined sectors are zero."
    },
    "scan_interrupted_status": {
        "it": "Scansione interrotta. Elaborati {0} su {1} ({2:.1f}%).",
        "en": "Scan interrupted. Processed {0} of {1} ({2:.1f}%)."
    },
    
    # Rewrite messages
    "no_sectors_to_rewrite": {
        "it": "Nessun settore da riscrivere.",
        "en": "No sectors to rewrite."
    },
    "cannot_open_log": {
        "it": "Impossibile aprire il file di log: {0}",
        "en": "Cannot open log file: {0}"
    },
    "cannot_open_drive": {
        "it": "Impossibile aprire {0} in scrittura: {1}",
        "en": "Cannot open {0} for writing: {1}"
    },
    "starting_rewrite": {
        "it": "Inizio riscrittura dei settori non zero...",
        "en": "Starting to rewrite non-zero sectors..."
    },
    "press_ctrl_c_rewrite": {
        "it": "Per interrompere la riscrittura, premi Ctrl+C",
        "en": "To interrupt the rewrite, press Ctrl+C"
    },
    "rewrite_completed": {
        "it": "Riscrittura completata.",
        "en": "Rewrite completed."
    },
    "rewrite_interrupted": {
        "it": "Riscrittura interrotta dall'utente (Ctrl+C).",
        "en": "Rewrite interrupted by user (Ctrl+C)."
    },
    "sectors_rewritten": {
        "it": "Riscritti {0} settori su {1} totali.",
        "en": "Rewritten {0} sectors out of {1} total."
    },
    "sectors_already_zeroed": {
        "it": "I settori già riscritti sono stati azzerati correttamente.",
        "en": "The sectors already rewritten have been zeroed correctly."
    },
    
    # Error messages
    "read_error": {
        "it": "Errore di lettura dal disco {0}: {1}",
        "en": "Error reading from disk {0}: {1}"
    },
    "disk_unreadable": {
        "it": "Il disco sembra esistere ma non è leggibile. Impossibile procedere.",
        "en": "The disk seems to exist but is not readable. Cannot proceed."
    },
    "insufficient_permissions": {
        "it": "Errore: permessi insufficienti per aprire {0}. Esegui come Administrator.",
        "en": "Error: insufficient permissions to open {0}. Run as Administrator."
    },
    "disk_not_exist": {
        "it": "Errore: il disco {0} non esiste o non è accessibile.",
        "en": "Error: disk {0} does not exist or is not accessible."
    },
    "access_error": {
        "it": "Errore di accesso a {0}: {1}",
        "en": "Access error to {0}: {1}"
    },
    "unknown_size": {
        "it": "Impossibile determinare la dimensione del disco. La scansione continuerà senza indicatore di progresso.",
        "en": "Unable to determine disk size. The scan will continue without a progress indicator."
    },
    
    # Log file messages
    "log_scan_start": {
        "it": "=== INIZIO SCANSIONE DI {0} ===",
        "en": "=== STARTING SCAN OF {0} ==="
    },
    "log_date_time": {
        "it": "Data/ora: {0}",
        "en": "Date/time: {0}"
    },
    "log_disk_size": {
        "it": "Dimensione disco: {0}",
        "en": "Disk size: {0}"
    },
    "log_sector_size": {
        "it": "Dimensione settore: {0} byte",
        "en": "Sector size: {0} bytes"
    },
    "log_workers": {
        "it": "Worker: {0}",
        "en": "Workers: {0}"
    },
    "log_mode": {
        "it": "Modalità log: {0}",
        "en": "Log mode: {0}"
    },
    "log_divider": {
        "it": "======================================",
        "en": "======================================"
    },
    "log_nonzero_sector": {
        "it": "Offset {0} NON ZERO",
        "en": "Offset {0} NON ZERO"
    },
    "log_error": {
        "it": "ERRORE: {0}",
        "en": "ERROR: {0}"
    },
    "log_scan_result": {
        "it": "=== RISULTATO SCANSIONE ===",
        "en": "=== SCAN RESULT ==="
    },
    "log_time_taken": {
        "it": "Tempo impiegato: {0:.1f} secondi",
        "en": "Time taken: {0:.1f} seconds"
    },
    "log_bytes_processed": {
        "it": "Byte elaborati: {0}",
        "en": "Bytes processed: {0}"
    },
    "log_total_chunks": {
        "it": "Chunk totali: {0}",
        "en": "Total chunks: {0}"
    },
    "log_zero_chunks": {
        "it": "Chunk a zero: {0}",
        "en": "Zero chunks: {0}"
    },
    "log_nonzero_chunks": {
        "it": "Chunk con settori non-zero: {0}",
        "en": "Chunks with non-zero sectors: {0}"
    },
    "log_error_chunks": {
        "it": "Chunk con errori: {0} ({1})",
        "en": "Chunks with errors: {0} ({1})"
    },
    "log_nonzero_sectors_found": {
        "it": "Settori non azzerati trovati: {0}",
        "en": "Non-zero sectors found: {0}"
    },
    "log_nonzero_percentage": {
        "it": "Percentuale di settori non azzerati: {0:.6f}%",
        "en": "Percentage of non-zero sectors: {0:.6f}%"
    },
    "log_all_sectors_zero": {
        "it": "TUTTI I SETTORI SONO A ZERO.",
        "en": "ALL SECTORS ARE ZERO."
    },
    "log_scan_interrupted": {
        "it": "=== SCANSIONE INTERROTTA DALL'UTENTE ===",
        "en": "=== SCAN INTERRUPTED BY USER ==="
    },
    "log_completed_chunks": {
        "it": "Chunk completati: {0}/{1}",
        "en": "Completed chunks: {0}/{1}"
    },
    "log_incomplete_scan": {
        "it": "SCANSIONE INCOMPLETA - Risultati parziali",
        "en": "INCOMPLETE SCAN - Partial results"
    },
    "log_rewrite_start": {
        "it": "=== INIZIO RISCRITTURA ===",
        "en": "=== STARTING REWRITE ==="
    },
    "log_sectors_to_rewrite": {
        "it": "Settori da riscrivere: {0}",
        "en": "Sectors to rewrite: {0}"
    },
    "log_sector_rewritten": {
        "it": "Settore a offset {0} riscritto a zero",
        "en": "Sector at offset {0} rewritten to zero"
    },
    "log_rewrite_completed": {
        "it": "=== RISCRITTURA COMPLETATA ===",
        "en": "=== REWRITE COMPLETED ==="
    },
    "log_sectors_rewritten": {
        "it": "Settori riscritti: {0}",
        "en": "Sectors rewritten: {0}"
    },
    "log_write_errors": {
        "it": "Errori di scrittura: {0}",
        "en": "Write errors: {0}"
    },
    "log_rewrite_interrupted": {
        "it": "=== RISCRITTURA INTERROTTA DALL'UTENTE ===",
        "en": "=== REWRITE INTERRUPTED BY USER ==="
    },
    "log_sectors_rewritten_count": {
        "it": "Settori riscritti: {0}/{1}",
        "en": "Sectors rewritten: {0}/{1}"
    },
    
    # New language selection messages
    "select_language": {
        "it": "Seleziona la lingua / Select language:",
        "en": "Select language / Seleziona la lingua:"
    },
    "language_options": {
        "it": "  1. Italiano\n  2. English",
        "en": "  1. Italiano\n  2. English"
    },
    "enter_language_choice": {
        "it": "Inserisci la tua scelta [1/2]: ",
        "en": "Enter your choice [1/2]: "
    }
}

# Translation function
def T(key, *args):
    """
    Returns the translated string in the current language
    """
    if key not in TRANSLATIONS:
        return key
    
    if LANGUAGE not in TRANSLATIONS[key]:
        # Fallback to English if requested language is not available
        translated = TRANSLATIONS[key].get("en", key)
    else:
        translated = TRANSLATIONS[key][LANGUAGE]
        
    # Format the string with provided parameters
    if args:
        return translated.format(*args)
    
    return translated

# If you want to change the hardware sector size, modify it here (512 or 4096, etc.)
SECTOR_SIZE = 512

# "Large" read block for greater efficiency (e.g. 1 MB = 1024*1024)
READ_BLOCK_SIZE = 1024 * 1024

# Constants for Windows API
IOCTL_DISK_GET_LENGTH_INFO = 0x7405C
IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x70000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000

# Structures for Windows API
class DISK_GET_LENGTH_INFO(Structure):
    _fields_ = [("Length", c_ulonglong)]

class DISK_GEOMETRY(Structure):
    _fields_ = [
        ("Cylinders", c_ulonglong),
        ("MediaType", wintypes.BYTE),
        ("TracksPerCylinder", wintypes.DWORD),
        ("SectorsPerTrack", wintypes.DWORD),
        ("BytesPerSector", wintypes.DWORD)
    ]

def format_size(size_bytes):
    """
    Format byte sizes in a readable format
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes/1024:.2f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes/(1024**2):.2f} MB"
    elif size_bytes < 1024**4:
        return f"{size_bytes/(1024**3):.2f} GB"
    else:
        return f"{size_bytes/(1024**4):.2f} TB"

def is_admin():
    """
    Check if the script is running with administrative privileges
    """
    try:
        return windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def get_drive_capacity(drive_path):
    """
    Automatically get the disk capacity using Windows API
    """
    try:
        # Open the disk handle
        h_device = windll.kernel32.CreateFileW(
            drive_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )
        
        if h_device == -1:  # INVALID_HANDLE_VALUE
            return 0
        
        # Prepare buffer to receive data
        disk_length_info = DISK_GET_LENGTH_INFO()
        bytes_returned = wintypes.DWORD(0)
        
        # Execute IOCTL call
        result = windll.kernel32.DeviceIoControl(
            h_device,
            IOCTL_DISK_GET_LENGTH_INFO,
            None, 0,
            byref(disk_length_info), sizeof(disk_length_info),
            byref(bytes_returned),
            None
        )
        
        # Close the handle
        windll.kernel32.CloseHandle(h_device)
        
        if result:
            return disk_length_info.Length
            
    except Exception as e:
        print(T("error_occurred", e))
    
    return 0

def detect_sector_size(drive_path):
    """
    Detect the disk sector size
    """
    try:
        # Open disk handle
        h_device = windll.kernel32.CreateFileW(
            drive_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )
        
        if h_device == -1:  # INVALID_HANDLE_VALUE
            return SECTOR_SIZE
        
        # Prepare buffer to receive data
        disk_geometry = DISK_GEOMETRY()
        bytes_returned = wintypes.DWORD(0)
        
        # Execute IOCTL call
        result = windll.kernel32.DeviceIoControl(
            h_device,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            None, 0,
            byref(disk_geometry), sizeof(disk_geometry),
            byref(bytes_returned),
            None
        )
        
        # Close the handle
        windll.kernel32.CloseHandle(h_device)
        
        if result:
            return disk_geometry.BytesPerSector
            
    except Exception as e:
        print(T("error_occurred", e))
    
    # If failed, use the default value
    return SECTOR_SIZE

def list_physical_drives(max_drive=20):
    """
    List available Windows physical devices
    """
    drives_found = []
    inaccessible_drives = []
    
    for i in range(max_drive):
        path = fr"\\.\PhysicalDrive{i}"
        try:
            # Try to open for reading
            with open(path, 'rb') as f:
                # Verify if we can read from the disk
                try:
                    f.seek(0)
                    f.read(512)  # Try to read at least one sector
                    
                    # Try to get size and sector size
                    size = get_drive_capacity(path)
                    sector_size = detect_sector_size(path)
                    
                    # Try to get a descriptive name
                    model = "Unknown"
                    try:
                        import wmi
                        c = wmi.WMI()
                        for disk in c.Win32_DiskDrive():
                            if f"PhysicalDrive{i}" in disk.DeviceID:
                                model = disk.Model
                                break
                    except:
                        pass
                    
                    drives_found.append({
                        'path': path,
                        'model': model,
                        'size_bytes': size,
                        'sector_size': sector_size,
                        'index': i
                    })
                except IOError:
                    # Disk exists but is not readable
                    inaccessible_drives.append((path, T("disk_unreadable")))
            
        except FileNotFoundError:
            # Ignore drives that don't exist
            pass
        except PermissionError:
            # Disk exists but we don't have permissions
            inaccessible_drives.append((path, T("insufficient_permissions")))
        except Exception as e:
            # Other access errors for drives that exist
            if "PhysicalDrive" in path and "Cannot find" not in str(e):
                inaccessible_drives.append((path, T("access_error", path, str(e))))
    
    return drives_found, inaccessible_drives

def scan_drive_chunk(args):
    """
    Scan a single chunk of the disk
    """
    drive_path, offset, chunk_size, sector_size = args
    non_zero_offsets = []
    
    try:
        with open(drive_path, 'rb') as f:
            f.seek(offset)
            try:
                chunk_data = f.read(chunk_size)
                
                # Divide the chunk into sectors
                chunk_len = len(chunk_data)
                num_sectors = chunk_len // sector_size
                remainder = chunk_len % sector_size
                
                for i in range(num_sectors):
                    sector_offset = offset + (i * sector_size)
                    sector_data = chunk_data[i*sector_size:(i+1)*sector_size]
                    if any(b != 0 for b in sector_data):
                        non_zero_offsets.append(sector_offset)
                
                # Handle any partial sector at the end
                if remainder > 0:
                    partial_offset = offset + (num_sectors * sector_size)
                    partial_data = chunk_data[-remainder:]
                    if any(b != 0 for b in partial_data):
                        non_zero_offsets.append(partial_offset)
            except IOError as e:
                # Specific read error
                raise IOError(T("read_error", offset, e))
    
    except Exception as e:
        # Catch all other exceptions
        raise Exception(T("access_error", offset, e))
    
    return non_zero_offsets

def scan_drive(drive_path, log_filename, sector_size, total_size=0, workers=None, log_mode="detailed"):
    """
    Scan the disk in parallel to find non-zero sectors
    
    log_mode: "detailed" for detailed logging of each sector, "summary" for general statistics
    """
    # If size is not specified, try to determine it automatically
    if total_size == 0:
        total_size = get_drive_capacity(drive_path)
        
    if total_size == 0:
        print(T("unknown_size"))
    
    # Verify read access
    try:
        f = open(drive_path, 'rb')
        try:
            # Try to read at least one sector
            f.seek(0)
            f.read(sector_size)
        except IOError as e:
            print(T("read_error", drive_path, e))
            print(T("disk_unreadable"))
            sys.exit(1)
        finally:
            f.close()
    except PermissionError:
        print(T("insufficient_permissions", drive_path))
        sys.exit(1)
    except FileNotFoundError:
        print(T("disk_not_exist", drive_path))
        sys.exit(1)
    except OSError as e:
        print(T("access_error", drive_path, e))
        sys.exit(1)
    
    # Open the log file
    log_file = open(log_filename, 'w', encoding='utf-8')
    
    # Write initial information to the log
    log_file.write(f"{T('log_scan_start', drive_path)}\n")
    log_file.write(f"{T('log_date_time', time.strftime('%Y-%m-%d %H:%M:%S'))}\n")
    log_file.write(f"{T('log_disk_size', format_size(total_size))}\n")
    log_file.write(f"{T('log_sector_size', sector_size)}\n")
    log_file.write(f"{T('log_workers', workers if workers else os.cpu_count() or 4)}\n")
    log_file.write(f"{T('log_mode', log_mode)}\n")
    log_file.write(f"{T('log_divider')}\n\n")
    
    # Determine the number of worker threads
    if workers is None:
        workers = os.cpu_count() or 4
    
    print(T("scanning_drive", drive_path))
    print(T("disk_size", format_size(total_size)) if total_size > 0 else T("disk_size_unknown"))
    print(T("sector_size", sector_size))
    print(T("log_file", log_filename))
    print(T("using_workers", workers))
    print(f"\n{T('press_ctrl_c')}")
    
    all_non_zero_offsets = []
    start_time = time.time()
    
    # Divide the disk into chunks for parallel scanning
    chunks = []
    for chunk_offset in range(0, total_size, READ_BLOCK_SIZE):
        # Adjust the last chunk if necessary
        current_chunk_size = min(READ_BLOCK_SIZE, total_size - chunk_offset)
        chunks.append((drive_path, chunk_offset, current_chunk_size, sector_size))
    
    total_chunks = len(chunks)
    
    try:
        # Flag for controlled interruption
        completed_chunks = 0
        error_chunks = 0
        scan_stopped = False  # Flag to manage interruption
        
        # Counters for summary log
        zero_chunks = 0
        non_zero_chunks = 0
        
        # Use tqdm for progress bar
        with tqdm(total=total_chunks, desc="Scanning", unit="chunk") as pbar:
            # Create a limited worker pool
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                # Smaller work batches to better handle interruption
                batch_size = min(100, len(chunks))
                processed = 0
                
                while processed < len(chunks) and not scan_stopped:
                    # Take the next batch of chunks to process
                    end_idx = min(processed + batch_size, len(chunks))
                    current_batch = chunks[processed:end_idx]
                    
                    # Execute the current batch and wait for all to complete
                    futures = []
                    for chunk in current_batch:
                        futures.append(executor.submit(scan_drive_chunk, chunk))
                    
                    # Process results as they complete
                    try:
                        for future in concurrent.futures.as_completed(futures):
                            try:
                                chunk_results = future.result()
                                all_non_zero_offsets.extend(chunk_results)
                                
                                # Update counters for statistics
                                if chunk_results:
                                    non_zero_chunks += 1
                                else:
                                    zero_chunks += 1
                                
                                # Write the newly found offsets to the log if in detailed mode
                                if log_mode == T("log_mode_detailed_name") and chunk_results:
                                    for offset in chunk_results:
                                        log_file.write(f"{T('log_nonzero_sector', offset)}\n")
                                
                                # Update the progress bar
                                pbar.update(1)
                                completed_chunks += 1
                                elapsed = time.time() - start_time
                                
                                # Update statistics in the bar
                                pbar.set_postfix({
                                    'found': len(all_non_zero_offsets),
                                    'time': f"{elapsed:.1f}s"
                                })
                                
                            except Exception as e:
                                error_message = T("error_occurred", e)
                                print(error_message)
                                log_file.write(f"{T('log_error', error_message)}\n")
                                error_chunks += 1
                                pbar.update(1)  # Update the bar anyway
                    
                    except KeyboardInterrupt:
                        # Handle keyboard interruption (Ctrl+C)
                        print(f"\n\n{T('scan_interrupted')}")
                        scan_stopped = True
                        
                        # Cancel all futures not yet completed
                        for future in futures:
                            future.cancel()
                        
                        # Let the for loop complete to process already obtained results
                    
                    # Update the processing index
                    processed = end_idx
        
        # Final results
        elapsed_time = time.time() - start_time
        bytes_processed = completed_chunks * READ_BLOCK_SIZE
        
        # Calculate additional statistics
        percent_complete = (completed_chunks / total_chunks) * 100 if total_chunks > 0 else 0
        non_zero_percentage = (len(all_non_zero_offsets) / (completed_chunks * READ_BLOCK_SIZE / sector_size)) * 100 if completed_chunks > 0 else 0
        
        if scan_stopped:
            print(T("scan_interrupted_status", format_size(bytes_processed), format_size(total_size), percent_complete))
            print(T("sectors_found_so_far", len(all_non_zero_offsets)))
            
            # Log of the interruption
            log_file.write(f"\n{T('log_scan_interrupted')}\n")
            log_file.write(f"{T('log_time_taken', elapsed_time)}\n")
            log_file.write(f"{T('log_bytes_processed', format_size(bytes_processed))} ({percent_complete:.1f}% {T('of_total')})\n")
            
            # Statistics for both log modes
            log_file.write(f"{T('log_completed_chunks', completed_chunks, total_chunks)}\n")
            log_file.write(f"{T('log_zero_chunks', zero_chunks)}\n")
            log_file.write(f"{T('log_nonzero_chunks', non_zero_chunks)}\n")
            
            if error_chunks > 0:
                log_file.write(f"{T('log_error_chunks', error_chunks, format_size(error_chunks * READ_BLOCK_SIZE))}\n")
            
            log_file.write(f"{T('log_nonzero_sectors_found', len(all_non_zero_offsets))}\n")
            log_file.write(f"{T('log_nonzero_percentage', non_zero_percentage)}\n")
            log_file.write(f"{T('log_incomplete_scan')}\n")
        else:
            print(T("scan_completed", elapsed_time))
            print(T("total_bytes_processed", format_size(bytes_processed)))
            
            if error_chunks > 0:
                print(T("error_chunks_warning", error_chunks, format_size(error_chunks * READ_BLOCK_SIZE)))
            
            # Log of final results
            log_file.write(f"\n{T('log_scan_result')}\n")
            log_file.write(f"{T('log_time_taken', elapsed_time)}\n")
            log_file.write(f"{T('log_bytes_processed', format_size(bytes_processed))}\n")
            
            # Statistics for both log modes
            log_file.write(f"{T('log_total_chunks', completed_chunks)}\n")
            log_file.write(f"{T('log_zero_chunks', zero_chunks)}\n")
            log_file.write(f"{T('log_nonzero_chunks', non_zero_chunks)}\n")
            
            if error_chunks > 0:
                log_file.write(f"{T('log_error_chunks', error_chunks, format_size(error_chunks * READ_BLOCK_SIZE))}\n")
            
            if all_non_zero_offsets:
                print(T("found_nonzero_sectors", len(all_non_zero_offsets)))
                log_file.write(f"{T('log_nonzero_sectors_found', len(all_non_zero_offsets))}\n")
                log_file.write(f"{T('log_nonzero_percentage', non_zero_percentage)}\n")
            else:
                print(T("all_sectors_zero"))
                log_file.write(f"{T('log_all_sectors_zero')}\n")
    
    except KeyboardInterrupt:
        # Handle keyboard interruption (Ctrl+C) at main level
        print(f"\n\n{T('scan_interrupted')}")
        print(T("sectors_found_so_far", len(all_non_zero_offsets)))
        
        log_file.write(f"\n{T('log_scan_interrupted')}\n")
        log_file.write(f"{T('log_time_taken', time.time() - start_time)}\n")
        log_file.write(f"{T('log_bytes_processed', format_size(completed_chunks * READ_BLOCK_SIZE))}\n")
        
        # Basic statistics for summary log
        log_file.write(f"{T('log_completed_chunks', completed_chunks, total_chunks)}\n")
        log_file.write(f"{T('log_zero_chunks', zero_chunks)}\n")
        log_file.write(f"{T('log_nonzero_chunks', non_zero_chunks)}\n")
        
        if error_chunks > 0:
            log_file.write(f"{T('log_error_chunks', error_chunks, format_size(error_chunks * READ_BLOCK_SIZE))}\n")
        
        log_file.write(f"{T('log_nonzero_sectors_found', len(all_non_zero_offsets))}\n")
    
    finally:
        # Close the log file in any case
        log_file.close()
    
    return all_non_zero_offsets

def rewrite_sectors(drive_path, offsets, sector_size, log_filename, log_mode="detailed"):
    """
    Rewrite specified sectors to zero with optimizations for better performance
    """
    if not offsets:
        print(T("no_sectors_to_rewrite"))
        return
    
    # Open the log file in append mode
    try:
        log_file = open(log_filename, 'a', encoding='utf-8')
        log_file.write(f"\n{T('log_rewrite_start')}\n")
        log_file.write(f"{T('log_date_time', time.strftime('%Y-%m-%d %H:%M:%S'))}\n")
        log_file.write(f"{T('log_sectors_to_rewrite', len(offsets))}\n")
    except Exception as e:
        print(T("cannot_open_log", e))
        return
    
    try:
        # Open in binary read/write with optimized buffering
        # Use a 1MB buffer to improve performance
        f = open(drive_path, 'r+b', buffering=1024*1024)
    except Exception as e:
        error_msg = T("cannot_open_drive", drive_path, e)
        print(error_msg)
        log_file.write(f"{T('log_error', error_msg)}\n")
        log_file.close()
        return
    
    print(T("starting_rewrite"))
    print(T("press_ctrl_c_rewrite"))
    
    try:
        # Counters for summary mode
        rewritten = 0
        errors = 0
        start_time = time.time()
        
        # Sort offsets to write sequentially when possible
        sorted_offsets = sorted(offsets)
        
        # Optimization: prepare a zero buffer once
        zero_data = b'\x00' * sector_size
        
        # Optimization: group contiguous offsets to write in larger blocks
        i = 0
        with tqdm(total=len(sorted_offsets), desc="Rewriting", unit="sector") as pbar:
            while i < len(sorted_offsets):
                current_offset = sorted_offsets[i]
                contiguous_count = 1
                
                # Find contiguous blocks of sectors
                while (i + contiguous_count < len(sorted_offsets) and 
                       sorted_offsets[i + contiguous_count] == current_offset + contiguous_count * sector_size):
                    contiguous_count += 1
                
                try:
                    # Position at the current offset
                    f.seek(current_offset, 0)
                    
                    if contiguous_count > 1:
                        # Write a block of contiguous sectors in a single operation
                        f.write(b'\x00' * (sector_size * contiguous_count))
                        
                        # Log only in detailed mode
                        if log_mode == T("log_mode_detailed_name"):
                            for j in range(contiguous_count):
                                offset = current_offset + j * sector_size
                                log_file.write(f"{T('log_sector_rewritten', offset)}\n")
                    else:
                        # Write a single sector
                        f.write(zero_data)
                        
                        # Log only in detailed mode
                        if log_mode == T("log_mode_detailed_name"):
                            log_file.write(f"{T('log_sector_rewritten', current_offset)}\n")
                    
                    # Force write to disk
                    f.flush()
                    
                    # Update counters and progress bar
                    rewritten += contiguous_count
                    pbar.update(contiguous_count)
                    
                except Exception as e:
                    error_msg = T("error_occurred", e)
                    print(error_msg)
                    log_file.write(f"{T('log_error', error_msg)}\n")
                    errors += contiguous_count
                    pbar.update(contiguous_count)
                
                # Move to the next block
                i += contiguous_count
        
        # Calculate time taken
        elapsed_time = time.time() - start_time
        
        print(T("rewrite_completed"))
        log_file.write(f"\n{T('log_rewrite_completed')}\n")
        log_file.write(f"{T('log_time_taken', elapsed_time)}\n")
        log_file.write(f"{T('log_sectors_rewritten', rewritten)}\n")
        if errors > 0:
            log_file.write(f"{T('log_write_errors', errors)}\n")
    
    except KeyboardInterrupt:
        # Calculate time taken
        elapsed_time = time.time() - start_time
        
        print(f"\n\n{T('rewrite_interrupted')}")
        print(T("sectors_rewritten", rewritten, len(offsets)))
        print(T("sectors_already_zeroed"))
        
        log_file.write(f"\n{T('log_rewrite_interrupted')}\n")
        log_file.write(f"{T('log_time_taken', elapsed_time)}\n")
        log_file.write(f"{T('log_sectors_rewritten_count', rewritten, len(offsets))}\n")
        if errors > 0:
            log_file.write(f"{T('log_write_errors', errors)}\n")
    
    finally:
        # Close the file in any case
        f.close()
        log_file.close()

def main():
    # Language selection at startup
    global LANGUAGE
    
    print("=" * 70)
    print("Disk Scanner - Non-Zero Sectors Finder")
    print("=" * 70)
    
    # Language selection
    print("\nSelect language / Seleziona la lingua:")
    print("  1. Italiano")
    print("  2. English")
    
    while True:
        lang_choice = input("Enter your choice / Inserisci la tua scelta [1/2]: ").strip()
        if lang_choice == "1":
            LANGUAGE = "it"
            break
        elif lang_choice == "2":
            LANGUAGE = "en"
            break
        print("Invalid choice / Scelta non valida")
    
    # Check if we're on Windows
    if os.name != 'nt':
        print(T("windows_only"))
        sys.exit(1)
    
    # Check administrative privileges
    if not is_admin():
        print(T("admin_warning"))
        print(T("admin_suggestion"))
    
    # Search for physical drives
    print(T("searching_drives"))
    drives, inaccessible_drives = list_physical_drives()
    
    if not drives:
        print(T("no_drives_found"))
        if inaccessible_drives:
            print(f"\n{T('inaccessible_drives')}")
            for path, reason in inaccessible_drives:
                print(f"  - {path}: {reason}")
        sys.exit(1)
    
    print(f"\n{T('available_drives')}")
    for i, drive in enumerate(drives):
        print(f"  {i+1}. {drive['path']} - {drive['model']} [{format_size(drive['size_bytes'])}]")
    
    if inaccessible_drives:
        print(f"\n{T('inaccessible_drives')}")
        for path, reason in inaccessible_drives:
            print(f"  - {path}: {reason}")
    
    # Drive selection
    while True:
        sel = input(f"\n{T('select_drive', len(drives))}").strip()
        try:
            idx = int(sel)
            if 1 <= idx <= len(drives):
                selected_drive = drives[idx-1]
                break
        except ValueError:
            pass
        print(T("invalid_choice"))
    
    # Log file name
    drive_num = selected_drive['path'].split('PhysicalDrive')[1]
    default_log_name = f"non_zero_sectors_drive{drive_num}.log"
    log_name = input(f"\n{T('enter_log_file', default_log_name)}").strip()
    if not log_name:
        log_name = default_log_name
    
    # Log mode
    print(f"\n{T('choose_log_mode')}")
    print(T("log_mode_detailed"))
    print(T("log_mode_summary"))
    while True:
        log_mode_sel = input(T("select_log_mode")).strip()
        if log_mode_sel == "1":
            log_mode = T("log_mode_detailed_name")
            break
        elif log_mode_sel == "2":
            log_mode = T("log_mode_summary_name")
            break
        print(T("invalid_choice"))
    
    # Confirm scan start
    sector_size = selected_drive['sector_size']
    print(f"\n{T('about_to_scan', selected_drive['path'], selected_drive['model'])}")
    print(T("size", format_size(selected_drive['size_bytes'])))
    print(T("sector_size", sector_size))
    print(T("log_file_mode", log_name, log_mode))
    
    # Request confirmation based on language
    if LANGUAGE == "it":
        confirm_char = "s"
        confirm_prompt = T("start_scan")
    else:  # English or other
        confirm_char = "y"
        confirm_prompt = T("start_scan")
    
    confirm = input(f"\n{confirm_prompt}").lower().strip()
    if confirm != confirm_char:
        print(T("operation_cancelled"))
        return
    
    # Start scan
    try:
        non_zero_offsets = scan_drive(
            drive_path=selected_drive['path'],
            log_filename=log_name,
            sector_size=sector_size,
            total_size=selected_drive['size_bytes'],
            log_mode=log_mode
        )
        
        if not non_zero_offsets:
            print(f"\n{T('no_zero_sectors')}")
            return
        
        # Ask if rewrite non-zero sectors
        ans = input(f"\n{T('rewrite_sectors', len(non_zero_offsets))}").lower().strip()
        if ans == confirm_char:
            rewrite_sectors(selected_drive['path'], non_zero_offsets, sector_size, log_name, log_mode)
        else:
            print(T("rewrite_cancelled"))
    
    except KeyboardInterrupt:
        # This KeyboardInterrupt is caught only if the user presses Ctrl+C
        # before the scan starts or after it completes
        print(f"\n{T('operation_interrupted')}")
    except Exception as e:
        print(f"\n{T('error_occurred', e)}")
        
    print(f"\n{T('program_terminated')}")

if __name__ == "__main__":
    main()