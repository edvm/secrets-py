# TopSecret

TopSecret is an encryption and decryption service with a REST API.

It provides two primary methods of encryption:

1. **Auto encryption**: Generates keys automatically and stores them securely
2. **Passphrase encryption**: Uses a user-provided passphrase for more secure encryption

The project includes a FastAPI web service that expose encryption functionality through HTTP endpoints, allowing users to encrypt sensitive information and share decryption URLs.

## Sponsorship

A special thanks to [Hamkee](https://hamkee.net/) for sponsoring the project and providing hosting services.

If you find this project useful, consider supporting its development:
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Donate-blue?style=social)](https://ko-fi.com/edvmfoss)


## Installation and Setup

### Prerequisites

- Python 3.10 or higher

Install `uv` (Linux and MacOS)
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Getting Started

Clone the repository:

```bash
git clone git@github.com:edvm/secrets-py.git
cd secrets-py 
```

### Using the Makefile

The project includes a Makefile trying to make your life easier. You can use it to automate common tasks. 

Be sure to have `make` and `uv` installed.

```bash
# Install dependencies
make install

# Run the API server
make run

# Run code quality checks (linting, type checking)
make check

# Run tests
make test

# Show all available commands
make help
```

### Running the API Server

After installation, start the API server:

```bash
make run
```

The API will be available at http://localhost:8000.

## Testing the API

### Using the API Documentation

Visit http://localhost:8000/docs for an interactive Swagger UI to test the API endpoints.

### Using curl

#### Testing the encrypt endpoint
```sh
# Example 1: Encrypt a secret without a passphrase
curl -X POST http://localhost:8000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"secret": "This is my top secret message"}'

# Example 2: Encrypt a secret with a passphrase
curl -X POST http://localhost:8000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"secret": "This is my password protected message", "passphrase": "mysecretpassword123"}'
```

#### Testing the decrypt endpoint
```sh
# Example 3: Decrypt a secret (replace HASH_VALUE with the actual hash from the encrypt response)
curl -X GET http://localhost:8000/decrypt/HASH_VALUE

# Example 4: Decrypt a passphrase-protected secret
curl -X GET "http://localhost:8000/decrypt/HASH_VALUE?passphrase=mysecretpassword123"
```

#### Example workflow

```sh
# Step 1: Encrypt a secret and capture the hash
RESPONSE=$(curl -s -X POST http://localhost:8000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"secret": "My super secret info"}'
)

# Step 2: Extract the hash from the response (requires jq)
HASH=$(echo $RESPONSE | jq -r '.hash')
echo "Hash: $HASH"

# Step 3: Decrypt using the hash
curl -X GET http://localhost:8000/decrypt/$HASH
```