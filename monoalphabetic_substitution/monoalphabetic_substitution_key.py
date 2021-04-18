from model.encryption_scheme.key import Key


class MonoalphabeticSubstitutionKey(Key):
    def __init__(self, mapping: dict):
        """ Takes in a mapping specifying how to encrypt a letter. """
        self._encoder_mapping = mapping
        self._decoder_mapping = {value: key for (key, value) in mapping.items()}

    def encode_letter(self, letter):
        return self._encoder_mapping[letter]

    def decode_letter(self, letter):
        return self._decoder_mapping[letter]
