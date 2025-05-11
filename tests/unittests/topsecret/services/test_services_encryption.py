import pytest

from topsecret.domain import CipherProtocol, CipherStorageProtocol, Metadata
from topsecret.services.encryption import EncryptionService


@pytest.fixture
def metadata() -> Metadata:
    """Metadata fixture for testing."""
    return {
        "method": "AUTO",
    }


@pytest.fixture
def mock_cipher(mocker):
    """Cipher mock for testing."""
    mock = mocker.Mock(spec=CipherProtocol, name="CipherMock")
    mock.encrypt.return_value = (b"encrypted_data", b"metadata")
    return mock


@pytest.fixture
def mock_storage(mocker, metadata: Metadata):
    """Storage mock for testing."""
    mock_storage = mocker.Mock(spec=CipherStorageProtocol, name="StorageMock")
    mock_storage.retrieve.return_value = (b"encrypted_data", metadata)
    return mock_storage


@pytest.fixture
def mock_hashfn(mocker):
    """Hash function mock for testing."""
    return mocker.Mock(name="HashFunctionMock", return_value="hashed_value")


@pytest.fixture
def encryption_service(mock_cipher, mock_storage, mock_hashfn) -> EncryptionService:
    """EncryptionService fixture for testing."""
    return EncryptionService(cipher=mock_cipher, storage=mock_storage, hashfn=mock_hashfn)


class TestEncryptionService:
    """EncryptionService tests."""

    def test_cipher_encrypt_is_called(self, encryption_service, mock_cipher):
        encryption_service.encrypt(data=b"some data")
        mock_cipher.encrypt.assert_called_once_with(b"some data", None)

    def test_cipher_storage_store_is_called(self, encryption_service, mock_storage):
        encryption_service.encrypt(data=b"some data")
        mock_storage.store.assert_called_once_with(key="hashed_value", value=(b"encrypted_data", b"metadata"))

    def test_cipher_hashfn_is_called(self, encryption_service, mock_hashfn):
        encryption_service.encrypt(data=b"some data")
        mock_hashfn.assert_called_once_with(b"encrypted_data")

    def test_cipher_storage_retrieve_is_called_on_decrypt(self, encryption_service, mock_storage):
        encryption_service.decrypt(hash_value="hashed_value", passphrase="test_passphrase")  # noqa: S106
        mock_storage.retrieve.assert_called_once_with(key="hashed_value")

    def test_cipher_decrypt_is_called(self, encryption_service, mock_cipher, metadata: Metadata):
        encryption_service.decrypt(hash_value="hashed_value", passphrase="test_passphrase")  # noqa: S106
        mock_cipher.decrypt.assert_called_once_with(b"encrypted_data", metadata, "test_passphrase")
