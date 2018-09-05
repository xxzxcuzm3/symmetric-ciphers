class Cipher:
    """The class describes the constructor of the classical cipher"""

    def __init__(self, plaintext=None, ciphertext=None):
        self.__pt = plaintext
        self.__ct = ciphertext
        self.__alphabet_len = 256

    def set_plaintext(self, pt):
        self.__pt = pt

    def get_plaintext(self):
        return self.__pt

    def set_ciphertext(self, ct):
        self.__ct = ct

    def get_ciphertext(self):
        return self.__ct

    def get_alphabet_len(self):
        return self.__alphabet_len

    @staticmethod
    def generate_eng_alphabet():
        return [chr(x) for x in range(97, 123)]


class CaesarCipher(Cipher):
    """Allows you to encrypt and decrypt text using Caesar"""

    def __init__(self, plaintext=None, ciphertext=None, decryption_shift=1):
        super().__init__(plaintext, ciphertext)
        self.__shift = int(decryption_shift)

    def set_shift(self, shift):
        self.__shift = int(shift)

    def get_shift(self):
        return self.__shift

    def encryption(self):
        result = [chr((ord(symbol) + self.get_shift()) % self.get_alphabet_len()) for symbol in self.get_plaintext()]
        self.set_ciphertext("".join(result))
        return self.get_ciphertext()

    def decrypt(self):
        result = [chr((ord(symbol) - self.get_shift() + self.get_alphabet_len()) % self.get_alphabet_len()) for symbol in self.get_ciphertext()]
        return "".join(result)


class VigenèreCipher(Cipher):
    """Allows you to encrypt and decrypt text using Vigenère Cipher"""

    def __init__(self, plaintext=None, ciphertext=None, start_key=None):
        super().__init__(plaintext, ciphertext)
        self.__key = start_key

    def set_start_key(self, start_key):
        self.__key = start_key

    def get_start_key(self):
        return self.__key

    def check_key(self):
        return True if len(self.get_start_key()) < len(self.get_plaintext()) else False

    def generate_key(self):
        if self.check_key():
            result = list(self.get_start_key())
            for symbol in result:
                result.append(symbol)
                if len(result) == len(self.get_plaintext()):
                    break
            return ''.join(result)
        else:
            return 'Check your plaintext\'s len. It can\'t be less then key\'s len!'

    def encryption(self):
        result = [chr((ord(symbol) + ord(self.generate_key()[i])) % self.get_alphabet_len()) for i, symbol in
                  enumerate(list(self.get_plaintext()))]
        self.set_ciphertext(''.join(result))
        return self.get_ciphertext()

    def decryption(self):
        result = [chr((ord(symbol) - ord(self.generate_key()[i])) % self.get_alphabet_len()) for i, symbol in
                  enumerate(list(self.get_ciphertext()))]
        return ''.join(result)
