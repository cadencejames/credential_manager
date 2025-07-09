import getpass
from credentials_loader import load_credentials
from cryptography.exceptions import InvalidTag

CREDENTIALS_FILE = "./credentials.enc"
def main_script_logic():
    # Main script logic. It first loads credentials and then uses them
    print("--- SCRIPT ---")
    try:
        # Prompt the user for the master password
        master_password = getpass.getpass("Enter the master password to unlock credentials: ")
        # Load and decrypt the credentials
        creds = load_credentials(CREDENTIALS_FILE, master_password)
        # Use the credentials
        db_user = creds.get('db-user')
        db_pass = creds.get('db-pass')
        print("\nCredentials loaded successfully!")
        print("Running script with...")
        print(f"  Database User: {db_user}")
        print(f"  Database Pass: {db_pass}") # <- THIS IS JUST FOR THE EXAMPLE. IN A REAL WORLD SCENARIO YOU WOULD NOT WANT TO OUTPUT THE PASSWORD IN CLEARTEXT.
    except (FileNotFoundError, InvalidTag):
        print("\nCould not load credentials. Aborting script.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main_script_logic()
