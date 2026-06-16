from caesar_cipher import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt

print('--- Caesar Cipher ---')
caesar_tests = [
    ('XYZ', 3),
    ('ABC', -1),
    ('Hello', 26),
    ('Hello', 30),
    ('', 5),
    ('12345', 7),
    ('Mix3D Ca5e!', 4),
    ('a', 25),
    ('Z', 1),
]
for text, shift in caesar_tests:
    enc = caesar_encrypt(text, shift)
    dec = caesar_decrypt(enc, shift)
    print(f'{text!r} (shift {shift}) -> {enc!r} -> {dec!r} | match: {dec == text}')

print()
print('--- Vigenere Cipher ---')
vigenere_tests = [
    ('Hello World', 'KEY'),
    ('ATTACK AT DAWN', 'lemon'),
    ('Cyber Security 2026!', 'Decode'),
    ('a', 'Z'),
    ('', 'KEY'),
]
for text, key in vigenere_tests:
    enc = vigenere_encrypt(text, key)
    dec = vigenere_decrypt(enc, key)
    print(f'{text!r} (key {key!r}) -> {enc!r} -> {dec!r} | match: {dec == text}')