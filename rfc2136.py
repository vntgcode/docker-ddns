""" RFC2136 client """

import logging
import dns.name
import dns.query
import dns.tsigkeyring
import dns.update
import dns.resolver


class Ddns:
    """RFC 2136 compliant dynamic DNS client."""

    def __init__(
        self,
        server: str,
        port: int,
        key_name: str,
        key_secret: str,
        key_algorithm: dns.name.Name,
        sign_query: bool = False,
        timeout: int = 300,
    ) -> None:
        """Initializes the DDNS client with the given parameters."""
        self.server = server
        self.port = port
        self.keyring = dns.tsigkeyring.from_text({key_name: key_secret})
        self.algorithm = key_algorithm
        self.sign_query = sign_query
        self._default_timeout = timeout
        # Setup logging
        self.logger = logging.getLogger("RFC2136")
        logging.basicConfig(level=logging.INFO)

    def _create_update_message(self, record_domain: str) -> dns.update.Update:
        """Helper to create a DNS update message."""
        return dns.update.UpdateMessage(
            record_domain, keyring=self.keyring, keyalgorithm=self.algorithm
        )

    def _check_record(
        self,
        record: str,
        record_domain: str,
        record_content: str,
        record_type: dns.rdatatype.ANY,
    ):
        """return true if record found and content matches"""
        try:
            r = f"{record}.{record_domain}"
            answer = dns.resolver.resolve_at(self.server, r, record_type)
            self.logger.info("record %s up to date: %s", r, answer[0])
            if str(answer[0]) == record_content:
                return True
            return False
        except dns.exception.DNSException:
            return False

    def add_a_record(
        self,
        record_domain: str,
        record_name: str,
        record_content: str,
        record_ttl: int = 300,
    ) -> None:
        """Add an 'A' record for a given domain and name."""
        if not self._check_record(
            record_name, record_domain, record_content, dns.rdatatype.A
        ):
            update = self._create_update_message(record_domain)
            update.replace(record_name, record_ttl, dns.rdatatype.A, record_content)
            self._send_update(update, record_domain, record_name)

    def _send_update(
        self, update: dns.update.UpdateMessage, record_domain: str, record_name: str
    ) -> None:
        """Send the update to the DNS server and handle response."""
        try:
            dns.query.tcp(update, self.server, timeout=self._default_timeout)
            self.logger.info(
                "DNS Update successful for  %s -> %s", record_domain, record_name
            )
        except dns.exception.DNSException as e:
            self.logger.error("Failed to update DNS for %s, %s", record_domain, e)
