from topsecret.domain import CipherStorageProtocol, Ciphertext, Hash, Metadata


class InMemStorage(CipherStorageProtocol):
    """An in-memory implementation of the CipherStorageProtocol.

    This class provides a simple, non-persistent storage mechanism using a Python
    dictionary. It is suitable for testing or scenarios where data persistence
    across sessions is not required.

    Attributes:
        data (dict[Hash, tuple[Ciphertext, Metadata]]): A dictionary to store
            ciphertexts and their associated metadata, keyed by a hash.
    """

    def __init__(self) -> None:
        """Initializes the InMemStorage.

        Sets up an empty dictionary to hold the stored data.
        """
        self.data: dict[Hash, tuple[Ciphertext, Metadata]] = {}

    def store(self, key: str, value: tuple[Ciphertext, Metadata]) -> None:
        """Stores a ciphertext and its metadata associated with a key.

        Args:
            key (str): The key under which to store the value.
            value (tuple[Ciphertext, Metadata]): A tuple containing the
                ciphertext and its associated metadata.
        """

        self.data[key] = value

    def retrieve(self, key: Hash) -> tuple[Ciphertext, Metadata]:
        """Retrieves the ciphertext and metadata associated with a key.

        Args:
            key (Hash): The key for which to retrieve the data.

        Returns:
            tuple[Ciphertext, Metadata]: The stored ciphertext and metadata.

        Raises:
            KeyError: If the key is not found in the storage.
        """
        return self.data[key]

    def contains(self, key: Hash) -> bool:
        """Checks if a key exists in the storage.

        Args:
            key (Hash): The key to check for.

        Returns:
            bool: True if the key exists in the storage, False otherwise.
        """
        return key in self.data
