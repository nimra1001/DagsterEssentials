import time
import base64
import logging
import pytz
from datetime import datetime, timedelta
from google.auth import default
from googleapiclient.discovery import build
from email.utils import parsedate_to_datetime
from bs4 import BeautifulSoup
from googleapiclient.errors import HttpError
import argparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailFetcher:
    SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

    def fetch_link_from_recent_email(self, subject_to_search):
        """Main function to fetch a link from recent email based on subject."""
        try:
            service = self.authenticate_gmail_service()
            user_id = self.get_authenticated_user(service)
            return self.search_email_for_link(service, user_id, subject_to_search)
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            return None

    def authenticate_gmail_service(self):
        """Authenticate using default credentials (already authenticated via gcloud command)."""
        try:
            creds, _ = default(scopes=self.SCOPES)
            service = build("gmail", "v1", credentials=creds, cache_discovery=False)
            logger.info("Gmail service authenticated successfully.")
            return service
        except Exception as e:
            logger.error(f"Failed to authenticate using application default credentials: {e}")
            return None

    def get_authenticated_user(self, service):
        """Get the profile of the authenticated user."""
        try:
            user_profile = service.users().getProfile(userId="me").execute()
            user_id = user_profile.get("emailAddress")
            logger.info(f"Authenticated as {user_id}.")
            return user_id
        except HttpError as error:
            logger.error(f"Failed to get user profile: {error}")
            return None

    def search_email_for_link(self, service, user_id, subject_to_search):
        """Search for an email matching the subject and extract the link."""
        RETRY_ATTEMPTS = 5
        WAIT_TIME = 5

        for attempt in range(RETRY_ATTEMPTS):
            logger.info(f"Attempt {attempt + 1} to retrieve emails from {user_id} inbox.")
            try:
                messages = self.fetch_inbox_messages(service)
                now = datetime.now(pytz.utc)
                for message in messages:
                    if self.is_matching_email(service, message, subject_to_search, now):
                        link = self.extract_link_from_email(service, message["id"])
                        return link
            except HttpError as error:
                logger.error(f"Failed to fetch or process emails: {error}")
                return None

            if attempt < RETRY_ATTEMPTS - 1:
                logger.info(f"Email with subject '{subject_to_search}' not found. Retrying after {WAIT_TIME} seconds.")
                time.sleep(WAIT_TIME)

        logger.info(f"No email found with subject '{subject_to_search}' after {RETRY_ATTEMPTS} attempts.")
        return None

    def fetch_inbox_messages(self, service):
        """Fetch the inbox messages."""
        try:
            result = service.users().messages().list(userId="me", labelIds=["INBOX"], maxResults=3).execute()
            messages = result.get("messages", [])
            if not messages:
                logger.info("No messages found in the inbox.")
            return messages
        except HttpError as error:
            logger.error(f"Failed to list emails: {error}")
            return None

    def is_matching_email(self, service, message, subject_to_search, now):
        """Check if an email matches the subject and is recent."""
        try:
            msg = service.users().messages().get(userId="me", id=message["id"], format="metadata").execute()
            headers = msg.get("payload", {}).get("headers", [])
            subject = next((header["value"] for header in headers if header["name"] == "Subject"), "No Subject")
            date_header = next((header["value"] for header in headers if header["name"] == "Date"), None)
            email_date = parsedate_to_datetime(date_header)

            if subject == subject_to_search and now - email_date <= timedelta(minutes=5):
                logger.info(f"Matching email found with subject: '{subject_to_search}'")
                return True
            return False
        except HttpError as error:
            logger.error(f"Failed to get email metadata: {error}")
            return False

    def extract_link_from_email(self, service, message_id):
        """Extract the link from an email body."""
        try:
            full_message = service.users().messages().get(userId="me", id=message_id, format="full").execute()
            for part in full_message["payload"].get("parts", []):
                if part["mimeType"] == "text/html":
                    html_content = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                    soup = BeautifulSoup(html_content, "html.parser")
                    link = soup.find("a", string=lambda text: text in ["Click here to create your password", "Click here to reset your password"])
                    if link:
                        return link["href"]
            logger.error("No link found in the email.")
            return None
        except HttpError as error:
            logger.error(f"Failed to get the full email: {error}")
            return None

def main(email_type):
    email_subjects = {
        "activation": "Action required: Create a password for your Galactic AI™ account",
        "forgotten password": "Reset your Galactic Web password",
    }

    email_subject = email_subjects.get(email_type.lower())
    if not email_subject:
        raise ValueError(f"Unknown email type: {email_type}")

    fetcher = EmailFetcher()
    link = fetcher.fetch_link_from_recent_email(email_subject)
    if link:
        logger.info(f"Link: {link}")
    else:
        logger.error(f"{email_type.capitalize()} link not found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch a specific link from an email")
    parser.add_argument("email_type", choices=["activation", "forgotten password"], help="The type of email to search for")
    args = parser.parse_args()
    main(args.email_type)
