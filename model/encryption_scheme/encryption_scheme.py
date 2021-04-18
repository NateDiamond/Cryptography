from abc import ABC, abstractmethod

from model.encryption_scheme.ciphertext import Ciphertext
from model.encryption_scheme.key import Key
from model.encryption_scheme.plaintext import Plaintext


class EncryptionScheme(ABC):
    """ An encryption scheme is fully defined by specifying the three
        algorithms (Gen, Enc, Dec) and a plaintext space M. """

    @abstractmethod
    def gen(self) -> Key:
        """ The key-generation algorithm Gen is a probabilistic algorithm that
            outputs a key k chosen according to some distribution that is
            determined be the scheme. """
        ...

    @abstractmethod
    def enc(self, k: Key, m: Plaintext) -> Ciphertext:
        """ The encryption algorithm Enc takes as input a key k and a plaintext
            message m and outputs a ciphertext c.
            c := Enc(k, m). """
        ...

    @abstractmethod
    def dec(self, k: Key, c: Ciphertext) -> Plaintext:
        """ The decryption algorithm Dec takes as input a key k and a ciphertext c
            and outputs a plaintext m"""
        ...

    @abstractmethod
    def assert_valid_plaintext(self, m: Plaintext):
        """ Asserts whether the input plaintext m is in this encryption scheme's
            plaintext space. """
        ...

    def assert_basic_correctness_requirement_met(self, k: Key, m: Plaintext):
        """ For a given key k and plaintext m, assert that enc composed with dec
            yields the original message m. """
        assert self.dec(k, self.enc(k, m)) == m
