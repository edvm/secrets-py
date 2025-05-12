# topsecret

`top secret` is an encryption and decryption service with a REST API.

It provides two primary methods of encryption:

1. **Auto encryption**: Generates keys automatically and stores them securely
2. **Passphrase encryption**: Uses a user-provided passphrase for more secure encryption

The project includes a FastAPI web service that expose encryption functionality through HTTP endpoints, allowing users to encrypt sensitive information and share decryption URLs.

## Sponsorship

A special thanks to [Hamkee](https://hamkee.net/) for sponsoring the project and providing hosting services.

If you find this project useful, consider supporting its development:
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Donate-blue?style=social)](https://ko-fi.com/edvmfoss)


## Run API on three simple steps 

### Prerequisites

- Python 3.10 or higher and `make` installed.

1- Install `uv` (Linux and MacOS)
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2- Run `make install` to install dependencies.
```bash
make install
```

3- Run `make run` to start the API server.
```bash
make run
```