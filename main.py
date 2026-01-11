import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pathlib import Path
from argparse import ArgumentParser

USERNAME = os.getlogin()
KEYNAME = USERNAME + '_root'
KEY_DIR = Path('keys')
KEY_DIR.mkdir(exist_ok=True)
PRVKEY_DIR = KEY_DIR / (KEYNAME + '.key')
PUBKEY_DIR = KEY_DIR / (KEYNAME + '.pub')

GREEN_START = '\033[32m'
YELLOW_START = '\033[33m'
RED_START = '\033[31m'
COL_STOP = '\033[0m'

parser = ArgumentParser()
parser.add_argument('--pub', help='Path to your recpient\'s public key')
parser.add_argument('--infile', help='Path to your input data')
args = parser.parse_args()

def main():
    if (not PRVKEY_DIR.is_file()) or (not PUBKEY_DIR.is_file()):
        gen_keypair(PRVKEY_DIR, name=KEYNAME)

    while True:
        options = [
            f'{YELLOW_START}Encrypt File{COL_STOP}',
            f'{YELLOW_START}Decrypt File{COL_STOP}',
            'Change Public Key',
            'Change Input File',
            f'{RED_START}Cancel{COL_STOP}'
        ]
        sel_idx = print_options_menu(options)

        if sel_idx == len(options)-1:
            return

        match sel_idx:
            case 0:
                if args.pub is None or args.infile is None:
                    cont_hook('Encryption requires setting both public-key and input-file!')
                    continue
                enc_pubk = Path(args.pub)
                data = Path(args.infile)
                if not enc_pubk.is_file() or not data.is_file():
                    cont_hook('Specified public key or data not found!')
                    continue
                Path('encrypted-file').write_bytes(
                    encrypt_for_recipient(
                        recipient_pubkey_bytes = enc_pubk.read_bytes(), 
                        plaintext = data.read_bytes()
                    )
                )
                cont_hook('Encryption completed succesfully: The file is stored as ./encrypted-file')
            case 1:
                if args.infile is None:
                    cont_hook('Decryption requires a valid encrypted input-file!')
                    continue
                data = Path(args.infile)
                if not data.is_file():
                    cont_hook('Input file not found!')
                    continue
                try:
                    out = decrypt_from_sender(ciphertext = data.read_bytes())
                except ValueError:
                    cont_hook('Provided input file is not a supported ciphertext!')
                    continue
                Path('decrypted-file').write_bytes(out)
                cont_hook('Decryption completed succesfully: The file is stored as ./decrypted-file\n Use file as-is or rename and change extension to whatever it is supposed to be.')
            case 2: 
                args.pub = print_prompt_menu(
                    'Enter path to new public key:',
                    lambda path: Path(path).is_file(),
                    'File not found -- try again.'
                )
            case 3:
                args.infile = print_prompt_menu(
                    'Enter path to new input file:',
                    lambda path: Path(path).is_file(),
                    'File not found -- try again.'
                )


def clear_screen():
    print("\033c", end="")
    print(f'Public-Key: {'<not given>' if args.pub is None else args.pub} | Input-File: {'<not given>' if args.infile is None else args.infile}')

def cont_hook(msg:str):
    print(msg)
    input(15*'='+'\nReady to restart? Hit enter:')
    return

def print_prompt_menu(txt_prompt: str, validator, txt_error: str = 'Invalid input, try again!'):
    msg = txt_prompt
    isFirstFail = True

    while True:
        clear_screen()
        user_in = input(msg)
        if validator(user_in):
            return user_in
        elif isFirstFail:
            msg = f'{txt_error}\n{txt_prompt}'
            isFirstFail = False

def print_options_menu(options : list[str]):
    while True:
        clear_screen()

        for row in enumerate(options, start=1):
            print(f"{GREEN_START}{row[0] :> 3}{COL_STOP} {row[1] : <20}")

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
    if path is not None and name is not None:
        path.with_name(name + '.key').write_bytes(private_key.private_bytes_raw())
        path.with_name(name + '.pub').write_bytes(public_key.public_bytes_raw())
    return (private_key, public_key)

def encrypt_for_recipient(recipient_pubkey_bytes: bytes, plaintext: bytes) -> bytes:
    recipient_pubkey = x25519.X25519PublicKey.from_public_bytes(recipient_pubkey_bytes)

    # Ephemeral key
    eph_private, eph_public = gen_keypair(None, None)

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
