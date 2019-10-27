from crypto.Util import number
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import binascii

# Program

def inv_mod(a, b):  # rozszerzony algorytm Euklidesa - liczenie odwrotności modulo
    u = 1
    w = a
    x = 0
    z = b
    q = 0

    while w!=0:
        if w < z:
            q = u  # q zmienna pomocnicza
            u = x
            x = q
            q = w
            w = z
            z = q

        q = w // z # dzielenie całkowitoliczbowe
        u = u - q * x
        w = w - q * z
    if z != 1:
        print("Brak rozwiazania!!!")
        return
    if x < 0:
        x += b
    return x

# dwie małe liczby
a = 49
b = 32

# dwie duże liczby - 1024 bitowe, losowe, pierwsze
c = number.getPrime(1024)
d = number.getPrime(1024)

def calculate():
    print("Male liczby:", a, b)

    print("Dodawanie:", a+b)
    print("Odejmowanie:", a-b)
    print("Mnożenie:", a*b)
    print("Odwrotność modulo:", inv_mod(a, b))

    print("\nDuże liczby:", c, '\n', d)
    print("Dodawawnie:", c+d)
    print("Odejmowanie:", c-d)
    print("Mnożenie:", c*d)
    print("Odwrotność modulo:", inv_mod(c, d))  # nie zawsze istnieje dla losowych liczb

key = b'ae!r@s9*5gy^&j8l'  # 16 * 8 bit = 128 bit klucz, znak b wymusza typ binarny zmiennej key
iv =  key # os.urandom(16)

# Szyfrowanie symetryczne AES
def encrypt(key, file_name, iv):
    print("\n*/Szyfrowanie symetryczne AES*/\n")
    # ustawienia AES
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    file_to_encrypt = open(file_name, 'rb')  # otwiera plik do zaszyfrowania
    data = file_to_encrypt.read()  # czytanie pliku
    file_to_encrypt.close()  # zamknięcie pliku
    padder = padding.PKCS7(128).padder()  # AES wymaga pełnych 128 bitowych bloków danych
    padded_data = padder.update(data) + padder.finalize()  # dopełnienie ostatniego bloku do 128 bitów
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize() # zaszyfrowanie
    encrypted = open('encrypted.enc', 'wb')  # utworzenie pliku do zapisu zaszyfrowanych danych
    encrypted.write(encrypted_data)  # zapis zaszyfrowanych danych
    encrypted.close()  # zamknięcie pliku z szyfrem

def decrypt(key, file_name, iv):
    print('Odszyfrowywanie...')
    decrypted_file = open('decrypted.txt', 'wb')  # otwarcie pliku do zapisu odszyfrowanych danych
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(open(file_name, 'rb').read()) + decryptor.finalize()  # otwarcie zaszyfrowanego pliku i jego odszyfrowanie

    try:
       unpader = padding.PKCS7(128).unpadder()  # po odszyfrowaniu należy usunąć dodane wcześniej dane dopełniające ostatni blok do 128 bitów
       decrypted = unpader.update(decrypted) + unpader.finalize()  # usunięcie dodanych danych
    except(ValueError):
        pass

    decrypted_file.write(decrypted)  # zapis odszyfrowanego pliku
    decrypted_file.close()  # zamknięcie pliku

#  obliczanie funkcji skrótu SHA256
def hash_func(file_name):
    print('Obliczanie funkcji skrotu...')
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(open(file_name, 'rb').read())
    hashed = digest.finalize()
    print("SHA256: ")
    print(binascii.hexlify(hashed))  # wypisanie skrótu w formie hexadecymalnej

calculate()
file_name = input("Podaj nazwe pliku do zaszyfrowania:")
enc_key = bytearray(input("Wprowadz 16 znakowy klucz szyfrujący:"), "utf8")
encrypt(enc_key, file_name, iv)
dec_key = bytearray(input("Wprowadz 16 znakowy klucz deszyfrujący:"), "utf8")
decrypt(dec_key, 'encrypted.enc', iv)
hash_func('text.txt')

