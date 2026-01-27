
# docker-ddns

This project provides dynamic DNS updates for Docker containers. It listens for Docker container start events and automatically updates DNS records for containers with the appropriate labels.

## Features
- Listens for Docker container start events in real time (no polling)
- Updates DNS records using RFC2136 for containers with `ddns.enable` label and Traefik host rules
- Configurable via Docker secrets or environment variables

## Usage

1. **Build the Docker image:**
	```sh
	docker build -t docker-ddns .
	```

2. **Run the container:**
	```sh
	docker run --rm \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  -e DNS_HOST=your_dns_server \
	  -e TSIG_NAME=your_tsig_name \
	  -e TSIG_KEY=your_tsig_key \
	  -e VALID_DOMAINS=example.com \
	  -e HOST_IP=1.2.3.4 \
	  docker-ddns
	```

3. **Label your containers:**
	- Add `ddns.enable=true` and a Traefik host rule label to any container you want to manage DNS for.

## How it works
- The service listens to Docker events and triggers a DNS update when a new container is started.
- Only containers with the `ddns.enable=true` label and a valid Traefik host rule are processed.

## Environment Variables / Secrets
- `DNS_HOST`: DNS server address
- `DNS_PORT`: DNS server port (default: 53)
- `TSIG_NAME`: TSIG key name
- `TSIG_KEY`: TSIG key value
- `TSIG_ALGO`: TSIG algorithm (default: HMAC-SHA256)
- `VALID_DOMAINS`: Comma-separated list of valid domains
- `HOST_IP`: IP address to assign in DNS records
- `DOCKER_URL`: (optional) Docker socket URL

## Requirements
- Docker socket must be mounted (`-v /var/run/docker.sock:/var/run/docker.sock`)
- Python 3.13+ (if running outside Docker)

## License
MIT
