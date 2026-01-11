import os
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from subprocess import call
from pathlib import Path
from argparse import ArgumentParser

KEYNAME = 'myroot'
KEY_DIR = Path('keys')
KEY_DIR.mkdir(exist_ok=True)
PRVKEY_DIR = KEY_DIR / (KEYNAME + '.key')
PUBKEY_DIR = KEY_DIR / (KEYNAME + '.pub')

CLEAR_COMMAND = 'cls' if os.name == 'nt' else 'clear'

class State(Enum):
    START = 0
    PROVISION = 1
    DATA = 2
    DONE = -1


def main():
    parser = ArgumentParser()
    parser.add_argument('--pub', help='Path to your recpient\'s public key')
    parser.add_argument('--infile', help='Path to your input data')
    args = parser.parse_args()
    
    if (not PRVKEY_DIR.is_file()) or (not PUBKEY_DIR.is_file()):
        gen_keypair(PRVKEY_DIR, name=KEYNAME)

    while True:
        options = [
            'Encrypt File',
            'Decrypt File',
            'Cancel'
        ]
        sel_idx = print_options_menu(options)

        if sel_idx == len(options)-1:
            break

        match sel_idx:
            case 0:
                if args.pub is None or args.infile is None:
                    print('Encryption requires setting both --pub and --infile argument!')
                    return
                enc_pubk = Path(args.pub)
                data = Path(args.infile)
                if not enc_pubk.is_file() or not data.is_file():
                    print('Specified public key or data not found!')
                    return

                Path('encrypted-file').write_bytes(
                    encrypt_for_recipient(
                        recipient_pubkey_bytes = enc_pubk.read_bytes(), 
                        plaintext = data.read_bytes()
                    )
                )
                print('Encryption completed succesfully: The file is stored as ./encrypted-file')
                
            case 1:
                data = Path(args.infile)
                if not data.is_file():
                    print('Specified data not found!')
                    return

                out = decrypt_from_sender(ciphertext = data.read_bytes())
                Path('decrypted-file').write_bytes(out)
                print('Decryption completed succesfully: The file is stored as ./decrypted-file')
                print('To use, rename and change file-type to whatever it is supposed to be.')
                



def print_prompt_menu(txt_prompt: str, validator, txt_error: str = 'Invalid input, try again!'):
    msg = txt_prompt
    isFirstFail = True

    while True:
        call(CLEAR_COMMAND)
        user_in = input(msg)
        if validator(user_in):
            return user_in
        elif isFirstFail:
            msg = f'{txt_error}\n{txt_prompt}'
            isFirstFail = False

def print_options_menu(options : list[str]):
    while True:
        call(CLEAR_COMMAND)

        for row in enumerate(options, start=1):
            print("{: >5} {: >20}".format(*row)) 
        
        try:
            idx = int(input(f'Enter index[1-{len(options)}]:'))
            if idx > 0 and idx <= len(options):
                # Return the index for selected option over the visible ID coz that may at least be useful
                return idx-1
        except ValueError:
            continue

def gen_keypair(path : Path, name : str):
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    path.with_name(name + '.key').write_bytes(private_key.private_bytes_raw())
    path.with_name(name + '.pub').write_bytes(public_key.public_bytes_raw())
    return (private_key, public_key)      

def encrypt_for_recipient(recipient_pubkey_bytes: bytes, plaintext: bytes) -> bytes:
    recipient_pubkey = x25519.X25519PublicKey.from_public_bytes(recipient_pubkey_bytes)

    # Ephemeral key
    eph_private, eph_public = gen_keypair(KEY_DIR/'ephemeral', name='ephemeral')

    # Shared secret
    shared = eph_private.exchange(recipient_pubkey)

    # Derive symmetric key
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"x25519-chacha20",
    ).derive(shared)

    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    # Store: eph_pub || nonce || ciphertext
    return (
        eph_public.public_bytes_raw()
        + nonce
        + ciphertext
    )

def decrypt_from_sender(ciphertext: bytes,) -> bytes:
    eph_pub_bytes = ciphertext[:32]
    nonce = ciphertext[32:44]
    payload = ciphertext[44:]

    # Load keys
    recipient_private = x25519.X25519PrivateKey.from_private_bytes(PRVKEY_DIR.read_bytes())
    eph_public = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)

    # Recompute shared secret
    shared = recipient_private.exchange(eph_public)

    # Derive symmetric key (must match encryption exactly)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"x25519-chacha20",
    ).derive(shared)

    # Decrypt
    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, payload, None)

    return plaintext


if __name__ == '__main__':
    main()