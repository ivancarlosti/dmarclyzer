import os
import imaplib
import email
import zipfile
import gzip
import io
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_dmarc_reports():
    """Connects to IMAP, finds unread emails, extracts XML reports, returns list of XML strings."""
    server = os.environ.get("IMAP_SERVER", "")
    port = int(os.environ.get("IMAP_PORT", "993"))
    user = os.environ.get("IMAP_USER", "")
    password = os.environ.get("IMAP_PASSWORD", "")
    folder = os.environ.get("IMAP_FOLDER", "INBOX")
    
    # Optional move folders
    move_folder = os.environ.get("IMAP_MOVE_FOLDER", "")
    move_folder_err = os.environ.get("IMAP_MOVE_FOLDER_ERR", "")

    xml_reports = []

    if not all([server, user, password]):
        logger.warning("IMAP credentials are not fully configured. Set them in .env.")
        return xml_reports

    try:
        logger.info(f"Connecting to IMAP {server}:{port}...")
        mail = imaplib.IMAP4_SSL(server, port)
        mail.login(user, password)
        status, folder_data = mail.select(folder)
        if status != 'OK':
            logger.error(f"Failed to select folder '{folder}'. Does it exist? (Note: Gmail folders are case-sensitive)")
            mail.logout()
            return xml_reports
            
        total_msgs = folder_data[0].decode() if folder_data and folder_data[0] else "0"
        logger.info(f"Successfully connected to '{folder}' (Total messages in folder: {total_msgs})")

        # Search for unread emails using UID
        status, messages = mail.uid('SEARCH', None, 'UNSEEN')
        if status != 'OK':
            logger.error("Failed to search emails.")
            return xml_reports

        msg_uids = messages[0].split()
        if not msg_uids:
            logger.info("No unread DMARC emails found.")

        # Flag to track if we need to expunge any deleted items
        msg_uids_to_expunge = False
        
        for msg_uid in msg_uids:
            res, msg_data = mail.uid('FETCH', msg_uid, '(RFC822)')
            if res != 'OK':
                continue
            
            msg_id_str = msg_uid.decode() if isinstance(msg_uid, bytes) else str(msg_uid)
            logger.info(f"Processing message ID: {msg_id_str}")
            found_xml_in_msg = False
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    for part in msg.walk():
                        if part.get_content_maintype() == 'multipart':
                            continue
                        if part.get('Content-Disposition') is None:
                            continue
                        
                        filename = part.get_filename()
                        if not filename:
                            continue

                        payload = part.get_payload(decode=True)
                        if not isinstance(payload, bytes):
                            continue

                        # Extract ZIP or GZ
                        try:
                            if filename.endswith('.zip'):
                                with zipfile.ZipFile(io.BytesIO(payload)) as z:
                                    for zinfo in z.namelist():
                                        if zinfo.endswith('.xml'):
                                            xml_reports.append(z.read(zinfo).decode('utf-8', errors='replace'))
                                            logger.info(f"Extracted XML from ZIP: {filename}")
                                            found_xml_in_msg = True
                            elif filename.endswith('.gz'):
                                with gzip.GzipFile(fileobj=io.BytesIO(payload)) as g:
                                    xml_reports.append(g.read().decode('utf-8', errors='replace'))
                                    logger.info(f"Extracted XML from GZ: {filename}")
                                    found_xml_in_msg = True
                            elif filename.endswith('.xml'):
                                xml_reports.append(payload.decode('utf-8', errors='replace'))
                                logger.info(f"Found direct XML attachment: {filename}")
                                found_xml_in_msg = True
                        except Exception as e:
                            logger.error(f"Error extracting attachment {filename}: {e}")
            
            # Determine destination folder
            dest_folder = move_folder_err
            if found_xml_in_msg:
                dest_folder = move_folder

            # Move the message if a destination folder is defined
            if dest_folder:
                dest_str = f'"{dest_folder}"' if ' ' in dest_folder else dest_folder
                try:
                    # Attempt to ensure the destination folder exists
                    try:
                        mail.create(dest_str)
                    except Exception:
                        pass # Often raises an exception if the folder already exists
                        
                    # 1. Copy to the new folder/label
                    res, _ = mail.uid('COPY', msg_uid, dest_str)
                    
                    if res == 'OK':
                        # 2. Add the deleted flag to the original message
                        mail.uid('STORE', msg_uid, '+FLAGS', '(\\Deleted)')
                        msg_uids_to_expunge = True
                        logger.info(f"Successfully copied message {msg_id_str} to {dest_folder} and marked original for deletion")
                    else:
                        logger.error(f"Failed to copy message {msg_id_str} to {dest_folder}")
                except Exception as e:
                    logger.error(f"Error moving message {msg_id_str} to {dest_folder}: {e}")

        # Delete the moved messages from the original folder
        if msg_uids_to_expunge:
            mail.expunge()
            logger.info("Expunged moved messages from original folder.")

        mail.close()
        mail.logout()

    except Exception as e:
        logger.error(f"IMAP Error: {e}")

    return xml_reports
