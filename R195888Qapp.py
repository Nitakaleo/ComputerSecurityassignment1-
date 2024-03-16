import streamlit as st
import random

# Function to encrypt plaintext using Caesar cipher
def encrypt(plaintext, key):
    ciphertext = ""

    for c in plaintext:
        if c.isalpha():
            base = 'a' if c.islower() else 'A'
            c = chr((ord(c) - ord(base) + key) % 26 + ord(base))
        ciphertext += c

    return ciphertext

# Function to decrypt ciphertext using Caesar cipher
def decrypt(ciphertext, key):
    plaintext = ""

    for c in ciphertext:
        if c.isalpha():
            base = 'a' if c.islower() else 'A'
            c = chr((ord(c) - ord(base) - key + 26) % 26 + ord(base))
        plaintext += c

    return plaintext

def main():
    st.title("Caesar Cipher Brute Force Attack")

    plaintext = st.text_input("Enter the plaintext:")
    ciphertext = ""
    found_key = -1

    if plaintext:
        key = random.randint(2, 10)
        ciphertext = encrypt(plaintext, key)

        st.write("Ciphertext:", ciphertext)

        st.write("Brute force attack (decrypting ciphertext)...")
        for i in range(2, 11):
            decrypted_text = decrypt(ciphertext, i)
            st.write("Key:", i, "Decrypted Text:", decrypted_text)
            if decrypted_text == plaintext:
                found_key = i
                break

        if found_key != -1:
            st.write("Brute force found the secret key to be:", found_key)
        else:
            st.write("Brute force failed to find the secret key.")

        final_decryption = decrypt(ciphertext, key)
        st.write("Decoded Ciphertext:", final_decryption)

if __name__ == "__main__":
    main()
