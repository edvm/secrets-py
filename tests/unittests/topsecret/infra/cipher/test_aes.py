import pytest

from topsecret.domain import DecryptionError
from topsecret.infra.cipher.aes import PKCS7AESCipher, get_hash


class TestGetHash:
    """`get_hash` tests."""

    def test_get_hash_returns_consistent_results(self):
        """Test that get_hash returns the same hash for the same input"""
        data = b"test data"
        hash1 = get_hash(data)
        hash2 = get_hash(data)
        assert hash1 == hash2

    def test_get_hash_returns_string(self):
        """Test that get_hash returns a string"""
        data = b"test data"
        hash_result = get_hash(data)
        assert isinstance(hash_result, str)

    def test_get_hash_length_is_64(self):
        """Test that get_hash returns a 64-character string"""
        data = b"test data"
        hash_result = get_hash(data)
        assert len(hash_result) == 64

    def test_get_hash_different_inputs_produce_different_hashes(self):
        """Test that different inputs produce different hashes"""
        data1 = b"test data 1"
        data2 = b"test data 2"
        hash1 = get_hash(data1)
        hash2 = get_hash(data2)
        assert hash1 != hash2


class TestPKCS7AESCipher:
    """`PKCS7AESCipher`"""

    @pytest.fixture
    def aescipher(self):
        """Create an instance for testing"""
        return PKCS7AESCipher()

    def test_encrypt_without_passphrase_returns_bytes(self, aescipher):
        """Test encryption without a passphrase returns bytes"""
        ciphertext, _ = aescipher.encrypt(b"secret", "passphrase")
        assert isinstance(ciphertext, bytes)

    def test_encrypt_without_passphrase_uses_auto_method(self, aescipher):
        """Test encryption without a passphrase uses AUTO method"""
        _, metadata = aescipher.encrypt(b"secret")
        assert metadata["method"] == PKCS7AESCipher.MethodType.AUTO

    def test_encrypt_with_passphrase_returns_bytes(self, aescipher):
        """Test encryption with passphrase returns bytes"""
        ciphertext, _ = aescipher.encrypt(b"secret", "passphrase")
        assert isinstance(ciphertext, bytes)

    def test_encrypt_with_passphrase_has_sufficient_length(self, aescipher):
        """Test encryption with passphrase produces sufficient length output"""
        ciphertext, _ = aescipher.encrypt(b"secret", "passphrase")
        assert len(ciphertext) > 16

    def test_encrypt_with_passphrase_uses_passphrase_method(self, aescipher):
        """Test encryption with passphrase uses PASSPHRASE method"""
        _, metadata = aescipher.encrypt(b"secret", "passphrase")
        assert metadata["method"] == PKCS7AESCipher.MethodType.PASSPHRASE

    def test_encrypt_different_passphrase_different_result(self, aescipher):
        """Test that different passphrases produce different ciphertexts"""
        passphrase1 = "passphrase1"
        passphrase2 = "passphrase2"
        ciphertext1, _ = aescipher.encrypt(b"s", passphrase1)
        ciphertext2, _ = aescipher.encrypt(b"s", passphrase2)
        assert ciphertext1 != ciphertext2

    def test_decrypt_auto_mode_successful(self, aescipher):
        """Test decryption of data encrypted in auto mode"""
        ciphertext, metadata = aescipher.encrypt(b"secret")
        decrypted = aescipher.decrypt(ciphertext, metadata)
        assert decrypted == "secret"

    def test_decrypt_passphrase_mode_successful(self, aescipher):
        """Test decryption of data encrypted with a passphrase"""
        passphrase = "my secure passphrase"  # noqa: S105
        ciphertext, metadata = aescipher.encrypt(b"secret", passphrase)
        decrypted = aescipher.decrypt(ciphertext, metadata, passphrase)
        assert decrypted == "secret"

    def test_decrypt_missing_passphrase_raises_error(self, aescipher):
        """Test that decryption raises error when passphrase is required but not provided"""
        passphrase = "my secure passphrase"  # noqa: S105
        ciphertext, metadata = aescipher.encrypt(b"some", passphrase)
        with pytest.raises(DecryptionError, match="Passphrase required"):
            aescipher.decrypt(ciphertext, metadata)

    def test_decrypt_wrong_passphrase_raises_error(self, aescipher):
        """Test that decryption fails with an incorrect passphrase"""
        correct_passphrase = "correct passphrase"  # noqa: S105
        wrong_passphrase = "wrong passphrase"  # noqa: S105
        ciphertext, metadata = aescipher.encrypt(b"data", correct_passphrase)
        with pytest.raises(DecryptionError):
            aescipher.decrypt(ciphertext, metadata, wrong_passphrase)

    def test_decrypt_invalid_ciphertext_format_raises_error(self, aescipher):
        """Test that decryption raises error with invalid ciphertext format"""
        invalid_ciphertext = b"this is not valid ciphertext"
        metadata = {"method": PKCS7AESCipher.MethodType.AUTO}
        with pytest.raises(DecryptionError, match="Invalid ciphertext format"):
            aescipher.decrypt(invalid_ciphertext, metadata)

    def test_decrypt_unknown_method_raises_error(self, aescipher):
        """Test that decryption raises error with unknown encryption method"""
        metadata = {"method": "unknown_method"}
        with pytest.raises(DecryptionError, match="Unknown encryption method"):
            aescipher.decrypt(b"some", metadata)

    def test_roundtrip_special_chars_auto_mode(self, aescipher):
        """Test encryption and decryption of special characters in auto mode"""
        special_chars = "Hello, 世界! Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?`~".encode()
        ciphertext, metadata = aescipher.encrypt(special_chars)
        decrypted = aescipher.decrypt(ciphertext, metadata)
        assert decrypted == special_chars.decode("utf-8")

    def test_roundtrip_special_chars_passphrase_mode(self, aescipher):
        """Test encryption and decryption of special characters with passphrase"""
        special_chars = "Hello, 世界! Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?`~".encode()
        passphrase = "secure passphrase"  # noqa: S105
        ciphertext, metadata = aescipher.encrypt(special_chars, passphrase)
        decrypted = aescipher.decrypt(ciphertext, metadata, passphrase)
        assert decrypted == special_chars.decode("utf-8")
