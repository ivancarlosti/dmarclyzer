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
        mail.select(folder)

        # Search for unread emails
        status, messages = mail.search(None, 'UNSEEN')
        if status != 'OK':
            logger.error("Failed to search emails.")
            return xml_reports

        msg_ids = messages[0].split()
        if not msg_ids:
            logger.info("No unread DMARC emails found.")

        for msg_id in msg_ids:
            res, msg_data = mail.fetch(msg_id, '(RFC822)')
            if res != 'OK':
                continue
            
            msg_id_str = msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id)
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
                try:
                    res, _ = mail.copy(msg_id, dest_folder)
                    if res != 'OK':
                        # Try to create folder if it does not exist
                        mail.create(dest_folder)
                        res, _ = mail.copy(msg_id, dest_folder)
                    
                    if res == 'OK':
                        mail.store(msg_id, '+FLAGS', '\\Deleted')
                        logger.info(f"Moved message {msg_id_str} to {dest_folder}")
                    else:
                        logger.error(f"Failed to move message {msg_id_str} to {dest_folder}")
                except Exception as e:
                    logger.error(f"Error moving message: {e}")

        # Delete the moved messages
        if move_folder or move_folder_err:
            mail.expunge()

        mail.close()
        mail.logout()

    except Exception as e:
        logger.error(f"IMAP Error: {e}")

    return xml_reports
