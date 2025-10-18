from argon2 import PasswordHasher


ph = PasswordHasher()


def hash_password(pw: str) -> str:
return ph.hash(pw)


def verify_password(stored_hash: str, candidate: str) -> bool:
return ph.verify(stored_hash, candidate)
