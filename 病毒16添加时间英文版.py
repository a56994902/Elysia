import hashlib  # Import hashlib to calculate MD5 of files
import os  # Import os for file path operations
import logging  # Import logging to log events
import requests  # Import requests to send logs to a remote server
import tkinter as tk  # Import tkinter for GUI
from tkinter import filedialog, Text, Scrollbar  # Import tkinter components
from datetime import datetime  # Import datetime to handle timestamps

# Set up logging configuration
logging.basicConfig(filename='virus_detection.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_md5_from_file(filename):
    """Get the MD5 hash of a file."""
    try:
        with open(filename, 'rb') as file:
            file_content = file.read()  # Read file content
            file_md5 = hashlib.md5(file_content).hexdigest()  # Calculate MD5
            return file_md5
    except (IOError, OSError) as e:
        print(f"Error reading file: {e}")
        return None

def check_for_virus(file_md5, virus_db):
    """Check if a file's MD5 is in the virus database."""
    return file_md5 in virus_db  # Return True if found in the database

def upload_log_to_server(md5):
    """Upload virus detection log to a remote server."""
    log_data = {'md5': md5}
    try:
        response = requests.post('https://your-logging-server/api/log', json=log_data)
        if response.status_code == 200:
            print("Log upload successful.")
        else:
            print(f"Log upload failed: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error uploading log: {e}")

def scan_directory(directory, virus_db):
    """Recursively scan a directory for files and detect viruses."""
    results = []  # To store scan results
    for root, dirs, files in os.walk(directory):  # Traverse directory
        for file in files:
            file_path = os.path.join(root, file)  # Full file path
            file_md5 = get_md5_from_file(file_path)  # Get MD5
            if file_md5 is None:  # If MD5 is None, skip file
                results.append(f"Cannot read file: {file_path}, skipping.")
                continue

            results.append(f"File MD5: {file_md5}")

            virus_found = check_for_virus(file_md5, virus_db)  # Check for virus
            if virus_found:  # If virus detected
                results.append(f"Virus detected! MD5: {file_md5} in {file_path}")
                logging.info(f"Virus detected! MD5: {file_md5} in {file_path}")
                os.remove(file_path)  # Remove infected file
                results.append(f"Deleted file: {file_path}")  # Log deletion
            else:
                results.append(f"No virus found in {file_path}.")  # Normal output
    return results  # Return scan results

def start_scan():
    """Start scanning the selected folder."""
    path = filedialog.askdirectory()  # Open folder selection dialog
    if path:
        start_time = datetime.now()  # Record the start time
        results = scan_directory(path, virus_db)  # Execute scan
        end_time = datetime.now()  # Record the end time
        total_time = end_time - start_time  # Calculate total scan time
        display_results(results, start_time, total_time)  # Display scan results

def display_results(results, start_time, total_time):
    """Display scan results in the text box."""
    result_text.delete(1.0, tk.END)  # Clear text box
    result_text.insert(tk.END, f"Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n", 'header')
    result_text.insert(tk.END, f"Total scan time: {total_time}\n", 'header')
    result_text.insert(tk.END, "-" * 50 + "\n", 'header')  # Separator line
    for result in results:
        if "Virus detected" in result or "Deleted file" in result:  # If result indicates virus
            result_text.insert(tk.END, result + "\n", 'virus')  # Display in red
        else:
            result_text.insert(tk.END, result + "\n")  # Default display

def create_gui():
    """Create a graphical user interface (GUI)."""
    global result_text  # Declare global variable for access in other functions
    window = tk.Tk()  # Create main window
    window.title("Antivirus Software")  # Set window title
    window.geometry('1000x600')  # Set window size

    # Create welcome label
    label = tk.Label(window, text="Welcome to Antivirus Software", font=("Arial", 30))
    label.pack(pady=40)  # Place label in window with padding

    # Create scan folder button
    scan_folder_button = tk.Button(window, text="Scan Folder", command=start_scan)
    scan_folder_button.pack(pady=10)  # Place button in window with padding

    # Add a scrollable text box
    result_text = Text(window, wrap='word', height=25, width=100)
    result_text.pack(pady=15)  # Place text box in window with padding

    # Add scrollbar
    scrollbar = Scrollbar(window, command=result_text.yview)  # Link scrollbar to text box
    scrollbar.pack(side='right', fill='y')  # Place scrollbar on the right
    result_text.config(yscrollcommand=scrollbar.set)  # Configure text box scrollbar

    # Configure 'virus' tag color in text box
    result_text.tag_config('virus', foreground='red')  # Set 'virus' tag text color to red
    result_text.tag_config('header', font=('Arial', 14, 'bold'))  # Set header style

    window.mainloop()  # Start event loop to keep window open

if __name__ == "__main__":
    # Extended virus database (example MD5 values)
    virus_db = [
        'eda588c0ee78b585f645aa42eff1e57a',  # Trojan.Win32.FormatAll.V
        '19dbec50735b5f2a72d4199c4e184960',  # Trojan.Win32.MEMZ.A
        '815b63b8bc28ae052029f8cbdd7098ce',  # Virus.Win32.Blamon
        'c71091507f731c203b6c93bc91adedb6',  # Trojan.Win32.Disabler
        '0a456ffff1d3fd522457c187ebcf41e4',  # Worm.VBS.yuyun.A / Cantix.A
        '1aa4c64363b68622c9426ce96c4186f2',  # TrojanDownloader:Win32.Jadtre.B
        'd214c717a357fe3a455610b197c390aa',  # Virus.Win32.disttrackA
        'b14299fd4d1cbfb4cc7486d978398214',  # Virus.Win32.disttrackA
        'dffe6e34209cb19ebe720c457a06edd6',  # Trojan:Win32/Dynamer!rfn
        '512301c535c88255c9a252fdf70b7a03',  # Virus.Win32.Viking.A
        'd4a05ada747a970bff6e8c2c59c9b5cd',  # Virus.Win32.Viking.A
        'ad41ec81ab55c17397d3d6039752b0fd',  # Virus.Win32.Viking.A
        'a57db79f11a8c58d27f706bc1fe94e25',  # Virus.Win32.Viking.A
        'fc14eaf932b76c51ebf490105ba843eb',  # Net-Worm.Win32.Blaster.A
        '2a92da4b5a353ca41de980a49b329e7d',  # Net-Worm.Win32.Sasser.A
        '68abd642c33f3d62b7f0f92e20b266aa',  # Virus.Win32.Ramnit/Nimnul.A
        'ff5e1f27193ce51eec318714ef038bef',  # Virus.Win32.Ramnit/Nimnul.A
        '4c36884f0644946344fa847756f4a04e',  # Virus.Win32.Xorer.A
        '2391109c40ccb0f982b86af86cfbc900',  # Worm.Win32.Pabug
        '915178156c8caa25b548484c97dd19c1',  # Worm.Win32.AutoRun.xxx
        'dac5f1e894b500e6e467ae5d43b7ae3e',  # Ransom.Win32.WannaCryptor
        '84c82835a5d21bbcf75a61706d8ab549',  # Ransom.Win32.WannaCryptor
        '1de73f49db23cf5cc6e06f47767f7fda',  # Ransom.Win32.WannaRen
        '71b6a493388e7d0b40c83ce903bc6b04',  # Ransom.Win32.Petya
        'c3b01563139d5570b4406ce1d3b3eba5',  # Custom Python script
    ]
    create_gui()  # Create and start GUI