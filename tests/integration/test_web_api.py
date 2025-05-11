import os
from unittest.mock import mock_open, patch

import pytest
from fastapi.testclient import TestClient

from topsecret.adapters.webapi import api as web_api
from topsecret.adapters.webapi import static_dir
from topsecret.app import App


@pytest.fixture
def client():
    App._instance = None
    yield TestClient(web_api)
    App._instance = None


def test_custom_api_info(client):
    """Test API info endpoint."""
    response = client.get("/api/info")
    assert response.status_code == 200
    data = response.json()
    assert data["endpoints"] == {"encrypt": "/encrypt", "decrypt": "/decrypt/{hash}"}


def test_encrypt_without_passphrase(client):
    """Test encrypting without passphrase."""
    response = client.post("/encrypt", json={"secret": "test secret"})
    assert response.status_code == 200
    data = response.json()
    assert "hash" in data
    assert "decrypt_url" in data
    assert data["decrypt_url"].endswith(f"{data['hash']}")


def test_encrypt_with_passphrase(client):
    """Test encrypting with passphrase."""
    response = client.post("/encrypt", json={"secret": "test secret", "passphrase": "test123"})
    assert response.status_code == 200
    data = response.json()
    assert "hash" in data
    assert "decrypt_url" in data


def test_encrypt_empty_secret(client):
    """Test encrypting with empty secret fails validation."""
    response = client.post("/encrypt", json={"secret": ""})
    assert response.status_code == 422  # Validation error


def test_decrypt_without_passphrase(client):
    """Test decrypting a secret that was encrypted without passphrase."""
    encrypt_response = client.post("/encrypt", json={"secret": "my test secret"})
    hash_value = encrypt_response.json()["hash"]

    decrypt_response = client.post(f"/decrypt/{hash_value}", data=None)
    assert decrypt_response.status_code == 200
    assert decrypt_response.json()["secret"] == "my test secret"  # noqa: S105


def test_decrypt_with_passphrase(client):
    """Test decrypting with the correct passphrase."""
    encrypt_response = client.post("/encrypt", json={"secret": "protected secret", "passphrase": "mypass"})
    hash_value = encrypt_response.json()["hash"]

    decrypt_response = client.get(f"/decrypt/{hash_value}?passphrase=mypass")
    assert decrypt_response.status_code == 200
    assert decrypt_response.json()["secret"] == "protected secret"  # noqa: S105


def test_decrypt_with_wrong_passphrase(client):
    """Test decrypting with incorrect passphrase fails."""
    # First encrypt with passphrase
    encrypt_response = client.post("/encrypt", json={"secret": "protected secret", "passphrase": "correct"})
    hash_value = encrypt_response.json()["hash"]

    decrypt_response = client.get(f"/decrypt/{hash_value}?passphrase=wrong")
    assert decrypt_response.status_code == 401
    assert "Invalid passphrase" in decrypt_response.json()["detail"]


def test_decrypt_missing_passphrase(client):
    """Test decrypting without providing required passphrase."""
    encrypt_response = client.post("/encrypt", json={"secret": "need passphrase", "passphrase": "required"})
    hash_value = encrypt_response.json()["hash"]

    decrypt_response = client.get(f"/decrypt/{hash_value}")
    assert decrypt_response.status_code == 401
    assert "Passphrase required for decryption" in decrypt_response.json()["detail"]


def test_decrypt_nonexistent_hash(client):
    """Test decrypting a hash that doesn't exist."""
    response = client.get("/decrypt/nonexistenthash12345")
    assert response.status_code == 401
    assert "Ciphertext not found in storage." in response.json()["detail"]


@patch("os.path.isfile")
@patch("builtins.open", new_callable=mock_open)
def test_root_default_theme(mock_open_file, mock_isfile, client):
    """Test serving the default theme."""
    mock_isfile.side_effect = lambda path: "default.html" in path
    mock_open_file.return_value.read.return_value = "<html>Default Theme</html>"

    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.text == "<html>Default Theme</html>"

    # Verify it looked for the right file
    default_path = os.path.join(static_dir, "themes", "default.html")
    mock_isfile.assert_any_call(default_path)
    mock_open_file.assert_called_once_with(default_path)


@patch("os.path.isfile")
@patch("builtins.open", new_callable=mock_open)
def test_root_custom_theme(mock_open_file, mock_isfile, client):
    """Test serving a custom theme."""

    def is_file_side_effect(path):
        return "custom.html" in path

    mock_isfile.side_effect = is_file_side_effect
    mock_open_file.return_value.read.return_value = "<html>Custom Theme</html>"

    response = client.get("/?theme=custom")
    assert response.status_code == 200
    assert response.text == "<html>Custom Theme</html>"

    custom_path = os.path.join(static_dir, "themes", "custom.html")
    mock_isfile.assert_any_call(custom_path)
    mock_open_file.assert_called_once_with(custom_path)


@patch("os.path.isfile")
@patch("builtins.open", new_callable=mock_open)
def test_root_theme_fallback(mock_open_file, mock_isfile, client):
    """Test fallback to default theme on theme not found."""

    def is_file_side_effect(path):
        return "default.html" in path and "notfound.html" not in path

    mock_isfile.side_effect = is_file_side_effect
    mock_open_file.return_value.read.return_value = "<html>Fallback Theme</html>"

    response = client.get("/?theme=notfound")
    assert response.status_code == 200
    assert response.text == "<html>Fallback Theme</html>"

    notfound_path = os.path.join(static_dir, "themes", "notfound.html")
    default_path = os.path.join(static_dir, "themes", "default.html")
    mock_isfile.assert_any_call(notfound_path)
    mock_isfile.assert_any_call(default_path)
    mock_open_file.assert_called_once_with(default_path)


@patch("os.path.isfile")
def test_root_no_themes_error(mock_isfile, client):
    """Test error when no themes are available."""
    mock_isfile.return_value = False

    response = client.get("/")
    assert response.status_code == 500
    assert "Server configuration error" in response.json()["detail"]
    assert "Default theme file is missing" in response.json()["detail"]
