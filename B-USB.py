import hashlib
import requests
import time
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import qrcode
from io import BytesIO
import json

# VirusTotal API Key (Replace with yours)
API_KEY = ""


def get_file_hash(file_path, hash_type="sha256"):
    """Computes the hash of a given file."""
    hash_func = hashlib.new(hash_type)
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def select_file():
    """Opens a file explorer to choose a file."""
    file_path = filedialog.askopenfilename(initialdir="/media/pi", title="Select a File")
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)


def generate_qr_code(file_hash):
    """Generate a QR code linking to VirusTotal's report page."""
    url = f"https://www.virustotal.com/gui/file/{file_hash}"
    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    return img


def scan_file():
    """Scans the selected file using VirusTotal."""
    file_path = file_entry.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a file first!")
        return

    file_hash = get_file_hash(file_path)
    update_status("Checking file on VirusTotal...")

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": f"{API_KEY}"
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        try:
            data = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = data.get('malicious', 0)
            suspicious = data.get('suspicious', 0)
            undetected = data.get('undetected', 0)

            if malicious > 0 or suspicious > 0:
                update_status("File found on VirusTotal! Potentially malicious.")
                show_results(response.json())
                qr_image = generate_qr_code(file_hash)
                display_qr_code(qr_image)
            elif malicious == 0 and suspicious == 0 and undetected == 0:
                # All values are 0, wait and retry
                update_status("Analysis in progress... Waiting for results.")
                root.after(10000, scan_file)  # Retry after 10 seconds
            else:
                update_status("File found on VirusTotal! No significant threats detected.")
                show_results(response.json())
                qr_image = generate_qr_code(file_hash)
                display_qr_code(qr_image)

        except (KeyError, json.JSONDecodeError) as e:
            #print(f"Error processing response: {e}")
            update_status("Error processing VirusTotal response.")

    else:
        update_status("File not found. Uploading for analysis...")
        upload_file(file_path)


def upload_file(file_path):
    """Uploads a file to VirusTotal."""
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        try:
            data = response.json()
            upload_url = data.get('data')

            if upload_url is not None:
                with open(file_path, "rb") as f:
                    files = {"file": (file_path, f)}
                    headers = {
                        "accept": "application/json",
                        "x-apikey": API_KEY,
                    }
                    upload_response = requests.post(upload_url, files=files, headers=headers)

                if upload_response.status_code == 200:
                    #print("File uploaded successfully!")
                    update_status("File uploaded successfully! Waiting for analysis...")
                    scan_file()
                else:
                    #print("File upload failed:", upload_response.text)
                    update_status("Upload failed. Try again later.")
            else:
                #print("Failed to retrieve upload URL.")
                update_status("Failed to retrieve upload URL.")
        except requests.exceptions.JSONDecodeError:
            #print("Error decoding JSON response.")
            update_status("Error decoding JSON response from VirusTotal.")
    else:
        #print(f"Failed to get upload URL. Status code: {response.status_code}")
        update_status("Failed to get upload URL from VirusTotal.")


def update_status(message):
    """Updates the status label."""
    status_label.config(text=message)
    root.update_idletasks()


def show_results(file):
    """Displays scan results in the UI."""
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)

    # File type
    result_text.insert(tk.END, f"File Type(s): {', '.join(file['data']['attributes'].get('type_tags', ['Unknown']))}\n")

    # Last Analysis Stats
    result_text.insert(tk.END, "Last Stats:")

    for key, value in file["data"]["attributes"]["last_analysis_stats"].items():
        if key == "malicious" or key == "suspicious" or key == "undetected":
            result_text.insert(tk.END, f"\n{key.replace('-', ' ').title()}: {value}")

    result_text.config(state=tk.DISABLED)


def display_qr_code(image):
    """Displays the QR code in the UI."""
    try:
        qr_photo = tk.PhotoImage(data=image_to_bytes(image))
        qr_label.config(image=qr_photo)
        qr_label.image = qr_photo
    except tk.TclError as e:
        #print(f"Error displaying QR code: {e}")
        messagebox.showerror("Error", "Could not display QR code. There was an internal error.")


def image_to_bytes(image):
    """Converts the image to a byte stream for Tkinter."""
    byte_io = BytesIO()
    image.save(byte_io, format="PNG")
    byte_io.seek(0)
    return byte_io.read()


# UI Setup
root = tk.Tk()
root.title("VirusTotal File Scanner")
root.geometry("550x500")
root.configure(bg="#2E2E2E")

# Styles
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=10)
style.configure("TLabel", font=("Arial", 12), background="#2E2E2E", foreground="white")
style.configure("TFrame", background="#2E2E2E")

# Title
title_label = ttk.Label(root, text="VirusTotal File Scanner", font=("Arial", 16, "bold"))
title_label.pack(pady=10)

# File Selection
frame = ttk.Frame(root)
frame.pack(pady=5)
file_entry = ttk.Entry(frame, width=50)
file_entry.pack(side=tk.LEFT, padx=5)
browse_button = ttk.Button(frame, text="Browse", command=select_file)
browse_button.pack(pady=10)

# Scan Button
scan_button = ttk.Button(root, text="Scan File", command=scan_file)
scan_button.pack(pady=10)


# Status Label
status_label = ttk.Label(root, text="Status: Waiting for input...", wraplength=500)
status_label.pack(pady=5)

# Results Text Box
result_text = tk.Text(root, height=8, width=60, wrap=tk.WORD, state=tk.DISABLED, bg="#1E1E1E", fg="white")
result_text.pack(pady=10)

# QR Code Display
qr_label = tk.Label(root, bg="#2E2E2E")
qr_label.pack(pady=5)

# Run the app
root.mainloop()