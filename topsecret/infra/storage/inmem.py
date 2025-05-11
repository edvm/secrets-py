from topsecret.domain import CipherStorageProtocol, Ciphertext, Hash, Metadata


class InMemStorage(CipherStorageProtocol):
    def __init__(self) -> None:
        self.data: dict[Hash, tuple[Ciphertext, Metadata]] = {}

    def store(self, key: str, value: tuple[Ciphertext, Metadata]) -> None:
        self.data[key] = value

    def retrieve(self, key: Hash) -> tuple[Ciphertext, Metadata]:
        return self.data[key]

    def contains(self, key: Hash) -> bool:
        return key in self.data
