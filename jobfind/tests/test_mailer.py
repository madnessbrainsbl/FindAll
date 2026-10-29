"""Verify SMTP delivery and rejection without contacting a mail server."""
import smtplib
import unittest
from unittest.mock import patch

from jf import mailer


class MailerTests(unittest.TestCase):
    def settings(self, **changes):
        values = dict(recipient="recipient@example.org", subject="Проверка", body="Тестовое письмо",
                      sender="sender@example.org", sender_name="Test", smtp_user="sender@example.org",
                      password="synthetic-password", host="smtp.example.org", port=587, security="STARTTLS")
        values.update(changes)
        return values

    def test_starttls_before_credentials_and_one_delivery(self):
        with patch.object(mailer.smtplib, "SMTP") as transport:
            smtp = transport.return_value.__enter__.return_value
            smtp.send_message.return_value = {}
            mailer.send_one(**self.settings())
            self.assertEqual([call[0] for call in smtp.method_calls],
                             ["ehlo", "starttls", "ehlo", "login", "send_message"])
            message = smtp.send_message.call_args.args[0]
            self.assertEqual(message["To"], "recipient@example.org")
            self.assertEqual(message["Subject"], "Проверка")
            self.assertEqual(message.get_content().strip(), "Тестовое письмо")

    def test_ssl_uses_verified_tls_and_one_delivery(self):
        with patch.object(mailer.smtplib, "SMTP_SSL") as transport:
            smtp = transport.return_value.__enter__.return_value
            smtp.send_message.return_value = {}
            mailer.send_one(**self.settings(port=465, security="SSL"))
            context = transport.call_args.kwargs["context"]
            self.assertTrue(context.check_hostname)
            self.assertEqual([call[0] for call in smtp.method_calls], ["login", "send_message"])

    def test_invalid_settings_never_connect(self):
        invalid = [dict(recipient="invalid"), dict(sender="other@example.org"),
                   dict(sender_name="Test\r\nBcc: secret@example.org"), dict(subject="Test\nBcc: x"),
                   dict(subject=""), dict(body=""), dict(host=""), dict(port=0),
                   dict(port=65536), dict(security="PLAIN")]
        with patch.object(mailer.smtplib, "SMTP") as plain, patch.object(mailer.smtplib, "SMTP_SSL") as tls:
            for changes in invalid:
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    mailer.send_one(**self.settings(**changes))
            plain.assert_not_called()
            tls.assert_not_called()

    def test_authentication_failure_never_sends(self):
        with patch.object(mailer.smtplib, "SMTP") as transport:
            smtp = transport.return_value.__enter__.return_value
            smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Synthetic rejection")
            with self.assertRaises(smtplib.SMTPAuthenticationError):
                mailer.send_one(**self.settings())
            smtp.send_message.assert_not_called()

    def test_recipient_rejection_is_failure_without_retry(self):
        with patch.object(mailer.smtplib, "SMTP") as transport:
            smtp = transport.return_value.__enter__.return_value
            smtp.send_message.return_value = {"recipient@example.org": (550, b"Synthetic rejection")}
            with self.assertRaises(RuntimeError):
                mailer.send_one(**self.settings())
            smtp.send_message.assert_called_once()

    def test_connection_loss_after_send_is_not_retried(self):
        with patch.object(mailer.smtplib, "SMTP") as transport:
            smtp = transport.return_value.__enter__.return_value
            smtp.send_message.side_effect = smtplib.SMTPServerDisconnected("Synthetic interruption")
            with self.assertRaises(smtplib.SMTPServerDisconnected):
                mailer.send_one(**self.settings())
            smtp.send_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
