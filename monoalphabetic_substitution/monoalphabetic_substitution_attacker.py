from model.encryption_scheme.ciphertext import Ciphertext
from monoalphabetic_substitution.monoalphabetic_substitution_key import MonoalphabeticSubstitutionKey
from constants.constants import ENGLISH_LANGUAGE_LETTER_RANKINGS, ENGLIGH_LANGUAGE_LETTER_FREQUENCIES


class MonoalphabeticSubstitutionAttacker:
    def get_most_likely_key(self, c: Ciphertext) -> MonoalphabeticSubstitutionKey:
        """ Using the simple frequency of letters in the English language, determine
            the most likely key for this message. """
        letter_counts = {chr(i): 0 for i in range(65, 91)}
        for letter in c:
            letter_counts[letter] = letter_counts[letter] + 1
        letter_rankings = [letter for letter, _ in sorted(letter_counts.items(), key=lambda x: x[1])]
        mapping = {ENGLISH_LANGUAGE_LETTER_RANKINGS[i]: letter_rankings[i] for i in range(26)}
        return MonoalphabeticSubstitutionKey(mapping)

    def decrypt_for_letters_above_threshold(self,
                                            proposed_key: MonoalphabeticSubstitutionKey,
                                            c: Ciphertext,
                                            threshold: float):
        """ Decrypts a ciphertext c for all letters that are above threshold in frequency.
            For those that aren't, it leaves them in the original message as (*). """
        partially_decrypted_message = ""
        for letter in c:
            decoded_letter = proposed_key.decode_letter(letter)
            if ENGLIGH_LANGUAGE_LETTER_FREQUENCIES[decoded_letter] >= threshold:
                partially_decrypted_message += decoded_letter
            else:
                partially_decrypted_message += f"({letter})"
        return partially_decrypted_message
