""" This script will poll docker for running containers and add dns for matching labels"""

import logging
import sys
import re
from typing import Optional
import signal
import time
import docker
from get_docker_secret import get_docker_secret
import rfc2136

logging.basicConfig(
    level="INFO", format="%(asctime)s  %(name)s  %(levelname)s: %(message)s"
)
logger = logging.getLogger("DDNS")


def signal_handler(_, __):
    """handle ctrl+c"""
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def get_traefik_host(labels):
    """Get the Traefik hostname from the labels if it matches the 'rule' pattern."""
    search = r"traefik\.http\.routers\..*\.rule"

    for label in labels:
        match = re.search(search, label, re.IGNORECASE)
        if match:
            # Extract the host or return the label if needed
            record_search = r"Host\([\'|`](.*?)[\'|`]\)"
            record_match = re.search(record_search, labels[label], re.IGNORECASE)
            if record_match:
                return record_match.group(1)
    return None


def is_ddns_enabled(labels) -> bool:
    """Check if DDNS is enabled based on the 'ddns.enable' label."""
    return labels.get("ddns.enable") == "true"


def get_record(host, valid_list):
    """return host and domain part"""

    # Split and reverse
    parts = host.split(".")
    parts.reverse()

    # Try to match domain parts
    for index, _ in enumerate(parts):
        # Build the domain backwards
        domain = ".".join(parts[: index + 1][::-1])
        if domain in valid_list:
            # If there's a match, extract the remainder of the domain
            remaining_parts = ".".join(parts[index + 1 :][::-1])
            return remaining_parts, domain
    return None


def create_connection(url: str = None) -> docker.client:
    """Create docker connection return client"""
    try:
        if url:
            clnt = docker.DockerClient(base_url=url)
        else:
            clnt = docker.DockerClient.from_env()
        return clnt
    except docker.errors.DockerException  as e:
        logger.error(e)
        sys.exit(4)


def process_container(container, valid_list):
    """Process a single container and return it's details"""
    name = container.name
    labels = container.labels

    if not is_ddns_enabled(labels):
        return None  # Skip containers without DDNS enabled

    host = get_traefik_host(labels)
    if not host:
        return None  # Skip containers without a Traefik host

    record, domain = get_record(host, valid_list)
    return (name, host, record, domain)


def process_record(valid_records, ddns_client, ip):
    """Add records for container"""
    for name, _, record, domain in valid_records:
        logger.info("checking record %s for %s", record, name)
        ddns_client.add_a_record(domain, record, ip)


def get_dns_configuration() -> dict:
    """get secrets from docker"""
    dns_host: str = get_docker_secret("DNS_HOST", "127.0.0.1")
    dns_port: Optional[int] = int(get_docker_secret("DNS_PORT", 53))
    tsig_name: str = get_docker_secret("TSIG_NAME")
    tsig_key: str = get_docker_secret("TSIG_KEY")
    tsig_algo: str = get_docker_secret("TSIG_ALGO", "HMAC-SHA256")
    valid_domains: str = get_docker_secret("VALID_DOMAINS")
    host_ip: str = get_docker_secret("HOST_IP")
    polling: int = get_docker_secret("POLLING", 300)
    docker_url: Optional[str] = get_docker_secret("DOCKER_URL", None)

    # Handle missing or malformed valid_domains
    valid_domains_list: list = []
    if valid_domains:
        valid_domains_list = [domain.strip() for domain in valid_domains.split(",")]

    try:
        # Check if host ip is set
        if not host_ip:
            raise ValueError("HOST_IP is required but missing.")

        # Check if TSIG_KEY is set
        if not tsig_key:
            raise ValueError("TSIG_KEY is required but missing.")

        # Check if TSIG_NAME is set
        if not tsig_name:
            raise ValueError("TSIG_NAME is required but missing.")

        # Check if VALID_DOMAINS is set
        if not valid_domains:
            raise ValueError("VALID_DOMAINS is rquired but missing")

        return {
            "dns_host": dns_host,
            "dns_port": dns_port,
            "tsig_name": tsig_name,
            "tsig_key": tsig_key,
            "tsig_algo": tsig_algo,
            "valid_domains_list": valid_domains_list,
            "host_ip": host_ip,
            "polling": int(polling),
            "docker": docker_url
        }
    except ValueError as e:
        logger.error("%s", e)
        sys.exit(3)


def main():
    """Main method to manage Docker containers."""
    env_vars = get_dns_configuration()

    while True:
        clnt = create_connection(env_vars['docker'])
        containers = clnt.containers.list()

        # Process containers and filter valid results
        valid_records = [
            process_container(container, env_vars["valid_domains_list"])
            for container in containers
            if process_container(container, env_vars["valid_domains_list"]) is not None
        ]

        ddns_client = rfc2136.Ddns(
            env_vars["dns_host"],
            env_vars["dns_port"],
            env_vars["tsig_name"],
            env_vars["tsig_key"],
            env_vars["tsig_algo"],
        )

        process_record(valid_records, ddns_client, env_vars["host_ip"])

        if env_vars["polling"] < 1:
            logger.info("Polling disabled exiting")
            break

        time.sleep(env_vars["polling"])


if __name__ == "__main__":
    main()
