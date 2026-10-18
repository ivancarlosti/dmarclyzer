"""IMAP polling and DMARC aggregate attachment extraction.

Attachments come from third parties, so ZIP/GZIP payloads are read through
bounded streams and every configured mailbox name is validated and quoted
before it reaches an IMAP command.
"""

import email
import gzip
import imaplib
import io
import logging
import os
import ssl
import zipfile

from security import (
    OversizedPayloadError,
    bounded_read,
    env_int,
    quote_mailbox,
    validate_mailbox,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_ATTACHMENT_SUFFIXES = (".xml", ".zip", ".gz")


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name, default) or "").strip()


def _limits() -> dict:
    return {
        "attachment": env_int("MAX_ATTACHMENT_MB", 25, 1, 200) * 1024 * 1024,
        "xml": env_int("MAX_XML_MB", 10, 1, 100) * 1024 * 1024,
        "archive": env_int("MAX_ARCHIVE_UNCOMPRESSED_MB", 50, 1, 500) * 1024 * 1024,
        "entries": env_int("MAX_ZIP_ENTRIES", 10, 1, 1000),
    }


def _extract_from_zip(payload: bytes, limits: dict) -> list[str]:
    """Extract XML members from a ZIP without ever materialising a bomb."""
    reports: list[str] = []
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = [
            info
            for info in archive.infolist()
            if not info.is_dir() and info.filename.lower().endswith(".xml")
        ]
        if len(members) > limits["entries"]:
            raise OversizedPayloadError(
                f"ZIP contains more than {limits['entries']} XML members"
            )

        total = 0
        for info in members:
            if info.file_size > limits["xml"]:
                raise OversizedPayloadError("ZIP member exceeds the XML size limit")
            with archive.open(info) as member:
                raw = bounded_read(member, limits["xml"])
            total += len(raw)
            if total > limits["archive"]:
                raise OversizedPayloadError(
                    "ZIP exceeds the total uncompressed size limit"
                )
            reports.append(raw.decode("utf-8", errors="replace"))
    return reports


def _extract_from_gzip(payload: bytes, limits: dict) -> list[str]:
    """Extract a single XML document from a GZIP stream with a size cap."""
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
        raw = bounded_read(stream, limits["xml"])
    return [raw.decode("utf-8", errors="replace")]


def fetch_dmarc_reports():
    """Connect to IMAP, extract unread DMARC XML reports, and return them."""
    server = _env("IMAP_SERVER")
    port = env_int("IMAP_PORT", 993, 1, 65535)
    user = _env("IMAP_USER")
    password = _env("IMAP_PASSWORD")
    folder = _env("IMAP_FOLDER", "INBOX") or "INBOX"
    move_folder = _env("IMAP_MOVE_FOLDER")
    move_folder_err = _env("IMAP_MOVE_FOLDER_ERR")

    xml_reports: list[str] = []

    if not all([server, user, password]):
        logger.warning("IMAP credentials are not fully configured. Set them in .env.")
        return xml_reports

    try:
        folder = validate_mailbox(folder)
        if move_folder:
            move_folder = validate_mailbox(move_folder)
        if move_folder_err:
            move_folder_err = validate_mailbox(move_folder_err)
    except ValueError as exc:
        logger.error("Invalid IMAP folder configuration: %s", exc)
        return xml_reports

    limits = _limits()
    mail = None
    msgs_moved = False

    try:
        logger.info("Connecting to IMAP %s:%s...", server, port)
        mail = imaplib.IMAP4_SSL(
            server, port, ssl_context=ssl.create_default_context()
        )
        mail.login(user, password)
        status, folder_data = mail.select(quote_mailbox(folder))
        if status != "OK":
            logger.error(
                "Failed to select folder %r. Does it exist? "
                "(Note: Gmail folders are case-sensitive)",
                folder,
            )
            return xml_reports

        total_msgs = folder_data[0].decode() if folder_data and folder_data[0] else "0"
        logger.info(
            "Successfully connected to %r (Total messages in folder: %s)",
            folder,
            total_msgs,
        )

        status, messages = mail.uid("SEARCH", None, "UNSEEN")
        if status != "OK":
            logger.error("Failed to search emails.")
            return xml_reports

        msg_uids = messages[0].split() if messages and messages[0] else []
        if not msg_uids:
            logger.info("No unread DMARC emails found.")

        for msg_uid in msg_uids:
            res, msg_data = mail.uid("FETCH", msg_uid, "(RFC822)")
            if res != "OK":
                continue

            msg_id_str = msg_uid.decode() if isinstance(msg_uid, bytes) else str(msg_uid)
            logger.info("Processing message ID: %s", msg_id_str)
            found_xml_in_msg = False

            for response_part in msg_data:
                if not isinstance(response_part, tuple):
                    continue
                msg = email.message_from_bytes(response_part[1])
                for part in msg.walk():
                    if part.get_content_maintype() == "multipart":
                        continue
                    if part.get("Content-Disposition") is None:
                        continue

                    filename = part.get_filename()
                    if not filename:
                        continue

                    # Strip any path component the sender may have supplied.
                    filename = os.path.basename(str(filename).replace("\\", "/"))
                    lowered = filename.lower()
                    if not lowered.endswith(_ATTACHMENT_SUFFIXES):
                        continue

                    payload = part.get_payload(decode=True)
                    if not isinstance(payload, bytes) or not payload:
                        continue
                    if len(payload) > limits["attachment"]:
                        logger.error(
                            "Rejected attachment %r: exceeds MAX_ATTACHMENT_MB.",
                            filename,
                        )
                        continue

                    try:
                        if lowered.endswith(".zip"):
                            extracted = _extract_from_zip(payload, limits)
                        elif lowered.endswith(".gz"):
                            extracted = _extract_from_gzip(payload, limits)
                        else:
                            if len(payload) > limits["xml"]:
                                raise OversizedPayloadError(
                                    "XML attachment exceeds the XML size limit"
                                )
                            extracted = [payload.decode("utf-8", errors="replace")]
                    except Exception as exc:
                        logger.error(
                            "Rejected attachment %r (%s).",
                            filename,
                            type(exc).__name__,
                        )
                        continue

                    if extracted:
                        xml_reports.extend(extracted)
                        found_xml_in_msg = True
                        logger.info(
                            "Extracted %s XML report(s) from %r",
                            len(extracted),
                            filename,
                        )

            dest_folder = move_folder_err
            if found_xml_in_msg:
                dest_folder = move_folder

            if dest_folder:
                dest_str = quote_mailbox(dest_folder)
                try:
                    try:
                        mail.create(dest_str)
                    except Exception:
                        pass  # Usually raised when the folder already exists

                    res, _ = mail.uid("COPY", msg_uid, dest_str)
                    if res == "OK":
                        mail.uid("STORE", msg_uid, "+FLAGS", "(\\Deleted)")
                        msgs_moved = True
                        logger.info(
                            "Copied message %s to %r and marked original for deletion",
                            msg_id_str,
                            dest_folder,
                        )
                    else:
                        logger.error(
                            "Failed to copy message %s to %r",
                            msg_id_str,
                            dest_folder,
                        )
                except Exception as exc:
                    logger.error(
                        "Error moving message %s to %r (%s)",
                        msg_id_str,
                        dest_folder,
                        type(exc).__name__,
                    )

        if msgs_moved:
            mail.expunge()
            logger.info("Expunged moved messages from original folder.")

    except Exception as exc:
        logger.error("IMAP error (%s)", type(exc).__name__)
    finally:
        if mail is not None:
            try:
                mail.close()
            except Exception:
                logger.debug("IMAP close failed", exc_info=True)
            try:
                mail.logout()
            except Exception:
                logger.debug("IMAP logout failed", exc_info=True)

    return xml_reports
