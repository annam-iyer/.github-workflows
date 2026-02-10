import os
import logging

# Configuration for the Mock Application
LOG_LEVEL = "INFO"
APP_NAME = "SecretScannerTest"

def initialize_services():
    """
    Simulates the initialization of cloud services using
    environment variables and hardcoded placeholders for testing.
    """
    
    # 1. Adobe Client Secret Placeholder
    # Patterns for Adobe often look for 'p8e-' prefixes or high-entropy strings.
    # This is a fake token for testing secret scanning detection.
    adobe_client_secret = "p8e-example-token-12345-uvwxy-67890-abcde-fghij"
    
    # 2. Azure Shared Access Signature (SAS) Placeholder
    # GitHub looks for 'sig=' with specific entropy and 'se=' (expiry) parameters.
    # This mock string mimics an Azure Storage SAS token.
    azure_sas_token = (
        "sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacupx&"
        "se=2026-02-10T15:00:00Z&st=2026-02-10T07:00:00Z&spr=https&"
        "sig=FAKE-AZURE-TOKEN-STRING-FOR-TESTING-PURPOSES-ONLY-12345"
    )

    print(f"--- Starting {APP_NAME} ---")
    
    if adobe_client_secret and azure_sas_token:
        logging.info("Credential strings detected in source code (Testing Only).")
        return True
    return False

def main():
    # Setup basic logging
    logging.basicConfig(level=LOG_LEVEL)
    
    try:
        success = initialize_services()
        if success:
            print("Test script executed. Check your GitHub 'Security' tab.")
        else:
            print("Failed to initialize test strings.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
