import re
from random import randint

from model.encryption_scheme.ciphertext import Ciphertext
from model.encryption_scheme.plaintext import Plaintext
from monoalphabetic_substitution.monoalphabetic_substitution_key import MonoalphabeticSubstitutionKey


class MonoalphabeticSubstitution:
    def gen(self) -> MonoalphabeticSubstitutionKey:
        mapping = {}
        target_letters = [chr(i) for i in range(65, 91)]
        for current_letter_index in range(26):
            random_target = randint(0, 25 - current_letter_index)
            mapping[chr(65 + current_letter_index)] = target_letters.pop(random_target)
        return MonoalphabeticSubstitutionKey(mapping)

    def enc(self, k: MonoalphabeticSubstitutionKey, m: Plaintext) -> Ciphertext:
        encrypted_message = ""
        for letter in m:
            encrypted_message += k.encode_letter(letter)
        return Ciphertext(encrypted_message)

    def dec(self, k: MonoalphabeticSubstitutionKey, c: Ciphertext) -> Plaintext:
        decrypted_message = ""
        for letter in c:
            decrypted_message += k.decode_letter(letter)
        return Plaintext(decrypted_message)

    def assert_valid_plaintext(self, m: Plaintext):
        assert re.fullmatch(r"[A-Z]*", m)
