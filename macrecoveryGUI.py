#!/usr/bin/env python3

"""
Mac Recovery Image Downloader (Unofficial - GUI Version)
"""

import argparse
import hashlib
import json
import linecache
import os
import random
import struct
import string
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from urllib.request import Request, HTTPError, urlopen
from urllib.parse import urlparse
import threading
import time

# Constants
SELF_DIR = os.path.dirname(os.path.realpath(__file__))
RECENT_MAC = 'Mac-27AD2F918AE68F61'
MLB_ZERO = '00000000000000000'
MLB_VALID = 'F5K105303J9K3F71M'
MLB_PRODUCT = 'F5K00000000K3F700'
TYPE_SID = 16
TYPE_K = 64
TYPE_FG = 64
INFO_PRODUCT = 'AP'
INFO_IMAGE_LINK = 'AU'
INFO_IMAGE_HASH = 'AH'
INFO_IMAGE_SESS = 'AT'
INFO_SIGN_LINK = 'CU'
INFO_SIGN_HASH = 'CH'
INFO_SIGN_SESS = 'CT'
INFO_REQURED = [INFO_PRODUCT, INFO_IMAGE_LINK, INFO_IMAGE_HASH, INFO_IMAGE_SESS, INFO_SIGN_LINK, INFO_SIGN_HASH, INFO_SIGN_SESS]
TERMINAL_MARGIN = 2

def run_query(url, headers, post=None, raw=False):
    if post is not None:
        data = '\n'.join(entry + '=' + post[entry] for entry in post).encode()
    else:
        data = None
    req = Request(url=url, headers=headers, data=data)
    try:
        response = urlopen(req)
        if raw:
            return response
        return dict(response.info()), response.read()
    except HTTPError as e:
        print(f'ERROR: "{e}" when connecting to {url}')
        sys.exit(1)


def generate_id(id_type, id_value=None):
    return id_value or ''.join(random.choices(string.hexdigits[:16].upper(), k=id_type))


def product_mlb(mlb):
    return '00000000000' + mlb[11:15] + '00'


def mlb_from_eeee(eeee):
    if len(eeee) != 4:
        print('ERROR: Invalid EEEE code length!')
        sys.exit(1)

    return f'00000000000{eeee}00'


def verify_chunklist(cnkpath):
    with open(cnkpath, 'rb') as f:
        hash_ctx = hashlib.sha256()
        data = f.read(ChunkListHeader.size)
        hash_ctx.update(data)
        magic, header_size, file_version, chunk_method, signature_method, chunk_count, chunk_offset, signature_offset = ChunkListHeader.unpack(data)
        assert magic == b'CNKL'
        assert header_size == ChunkListHeader.size
        assert file_version == 1
        assert chunk_method == 1
        assert signature_method in [1, 2]
        assert chunk_count > 0
        assert chunk_offset == 0x24
        assert signature_offset == chunk_offset + Chunk.size * chunk_count
        for _ in range(chunk_count):
            data = f.read(Chunk.size)
            hash_ctx.update(data)
            chunk_size, chunk_sha256 = Chunk.unpack(data)
            yield chunk_size, chunk_sha256
        digest = hash_ctx.digest()
        if signature_method == 1:
            data = f.read(256)
            assert len(data) == 256
            signature = int.from_bytes(data, 'little')
            plaintext = int(f'0x1{"f"*404}003031300d060960864801650304020105000420{"0"*64}', 16) | int.from_bytes(digest, 'big')
            assert pow(signature, 0x10001, Apple_EFI_ROM_public_key_1) == plaintext
        elif signature_method == 2:
            data = f.read(32)
            assert data == digest
            raise RuntimeError('Chunklist missing digital signature')
        else:
            raise NotImplementedError
        assert f.read(1) == b''

ChunkListHeader = struct.Struct('<4sIBBBxQQQ')
assert ChunkListHeader.size == 0x24

Chunk = struct.Struct('<I32s')
assert Chunk.size == 0x24

Apple_EFI_ROM_public_key_1 = 0xC3E748CAD9CD384329E10E25A91E43E1A762FF529ADE578C935BDDF9B13F2179D4855E6FC89E9E29CA12517D17DFA1EDCE0BEBF0EA7B461FFE61D94E2BDF72C196F89ACD3536B644064014DAE25A15DB6BB0852ECBD120916318D1CCDEA3C84C92ED743FC176D0BACA920D3FCF3158AFF731F88CE0623182A8ED67E650515F75745909F07D415F55FC15A35654D118C55A462D37A3ACDA08612F3F3F6571761EFCCBCC299AEE99B3A4FD6212CCFFF5EF37A2C334E871191F7E1C31960E010A54E86FA3F62E6D6905E1CD57732410A3EB0C6B4DEFDABE9F59BF1618758C751CD56CEF851D1C0EAA1C558E37AC108DA9089863D20E2E7E4BF475EC66FE6B3EFDCF

def get_session(args):
    headers = {
        'Host': 'osrecovery.apple.com',
        'Connection': 'close',
        'User-Agent': 'InternetRecovery/1.0',
    }

    headers, _ = run_query('http://osrecovery.apple.com/', headers)

    if args.verbose:
        print('Session headers:')
        for header in headers:
            print(f'{header}: {headers[header]}')

    for header in headers:
        if header.lower() == 'set-cookie':
            cookies = headers[header].split('; ')
            for cookie in cookies:
                return cookie if cookie.startswith('session=') else ...

    raise RuntimeError('No session in headers ' + str(headers))


def get_image_info(session, bid, mlb=MLB_ZERO, diag=False, os_type='default', cid=None):
    headers = {
        'Host': 'osrecovery.apple.com',
        'Connection': 'close',
        'User-Agent': 'InternetRecovery/1.0',
        'Cookie': session,
        'Content-Type': 'text/plain',
    }

    post = {
        'cid': generate_id(TYPE_SID, cid),
        'sn': mlb,
        'bid': bid,
        'k': generate_id(TYPE_K),
        'fg': generate_id(TYPE_FG)
    }

    if diag:
        url = 'http://osrecovery.apple.com/InstallationPayload/Diagnostics'
    else:
        url = 'http://osrecovery.apple.com/InstallationPayload/RecoveryImage'
        post['os'] = os_type

    headers, output = run_query(url, headers, post)

    output = output.decode('utf-8')
    info = {}
    for line in output.split('\n'):
        try:
            key, value = line.split(': ')
            info[key] = value
        except KeyError:
            continue
        except ValueError:
            continue

    for k in INFO_REQURED:
        if k not in info:
            return None # Indicate failure to retrieve all required information

    return info


def save_image(url, sess, filename='', directory='', callback=None):
    purl = urlparse(url)
    headers = {
        'Host': purl.hostname,
        'Connection': 'close',
        'User-Agent': 'InternetRecovery/1.0',
        'Cookie': '='.join(['AssetToken', sess])
    }

    if not os.path.exists(directory):
        os.makedirs(directory)

    if filename == '':
        filename = os.path.basename(purl.path)
    if filename.find(os.sep) >= 0 or filename == '':
        raise RuntimeError('Invalid save path ' + filename)

    with open(os.path.join(directory, filename), 'wb') as fh:
        response = run_query(url, headers, raw=True)
        headers = dict(response.headers)
        totalsize = -1
        for header in headers:
            if header.lower() == 'content-length':
                totalsize = int(headers[header])
                break
        size = 0
        while True:
            chunk = response.read(2**20)
            if not chunk:
                break
            fh.write(chunk)
            size += len(chunk)
            if callback:
                callback(size, totalsize)

    return os.path.join(directory, os.path.basename(filename))


def verify_image(dmgpath, cnkpath):
    print('Verifying image with chunklist...')

    with open(dmgpath, 'rb') as dmgf:
        for cnkcount, (cnksize, cnkhash) in enumerate(verify_chunklist(cnkpath), 1):
            terminalsize = max(os.get_terminal_size().columns - TERMINAL_MARGIN, 0)
            print(f'\r{f"Chunk {cnkcount} ({cnksize} bytes)":<{terminalsize}}', end='')
            sys.stdout.flush()
            cnk = dmgf.read(cnksize)
            if len(cnk) != cnksize:
                raise RuntimeError(f'Invalid chunk {cnkcount} size: expected {cnksize}, read {len(cnk)}')
            if hashlib.sha256(cnk).digest() != cnkhash:
                raise RuntimeError(f'Invalid chunk {cnkcount}: hash mismatch')
        if dmgf.read(1) != b'':
            raise RuntimeError('Invalid image: larger than chunklist')
        print('\nImage verification complete!')

def action_download(args, callback):
    try:
        session = get_session(args)
        info = get_image_info(session, bid=args.board_id, mlb=args.mlb, diag=args.diagnostics, os_type=args.os_type)
        if info:
            print(f'Downloading {info.get(INFO_PRODUCT, "Unknown Product")}...')
            save_image(info[INFO_SIGN_LINK], info[INFO_SIGN_SESS], args.basename + '.chunklist', args.outdir, callback)
            save_image(info[INFO_IMAGE_LINK], info[INFO_IMAGE_SESS], args.basename + '.dmg', args.outdir, callback)
            print("Download complete!")
            return 0  # Success
        else:
            print("Failed to retrieve image information.")
            return 1 #Failure

    except Exception as e:
        print(f"Error during download: {e}")
        return 1  # Failure

board_data = {
    "Mac-EE2EBD4B90B839A8": "13.7",
    "Mac-BE0E8AC46FE800CC": "11.7.10",
    "Mac-9AE82516C7C6B903": "12.7.6",
    "Mac-942452F5819B1C1B": "10.13.6",
    "Mac-942C5DF58193131B": "10.13.6",
    "Mac-C08A6BB70A942AC2": "10.13.6",
    "Mac-742912EFDBEE19B3": "10.13.6",
    "Mac-66F35F19FE2A0D05": "10.15.7",
    "Mac-2E6FAB96566FE58C": "10.15.7",
    "Mac-35C1E88140C3E6CF": "11.7.10",
    "Mac-7DF21CB3ED6977E5": "11.7.10",
    "Mac-9F18E312C5C2BF0B": "12.7.6",
    "Mac-937CB26E2E02BB01": "12.7.6",
    "Mac-827FAC58A8FDFA22": "14.7",
    "Mac-226CB3C6A851A671": "14.7",
    "Mac-0CFF9C7C2B63DF8D": "latest",
    "Mac-C3EC7CD22292981F": "10.15.7",
    "Mac-AFD8A9D944EA4843": "10.15.7",
    "Mac-189A3D4F975D5FFC": "11.7.10",
    "Mac-3CBD00234E554E41": "11.7.10",
    "Mac-2BD1B31983FE1663": "11.7.10",
    "Mac-06F11FD93F0323C5": "12.7.6",
    "Mac-06F11F11946D27C5": "12.7.6",
    "Mac-E43C1C25D4880AD6": "12.7.6",
    "Mac-473D31EABEB93F9B": "12.7.6",
    "Mac-66E35819EE2D0D05": "12.7.6",
    "Mac-A5C67F76ED83108C": "12.7.6",
    "Mac-B4831CEBD52A0C4C": "13.7",
    "Mac-CAD6701F7CEA0921": "13.7",
    "Mac-551B86E5744E2388": "13.7",
    "Mac-937A206F2EE63C01": "latest",
    "Mac-827FB448E656EC26": "latest",
    "Mac-1E7E29AD0135F9BC": "latest",
    "Mac-53FDB3D8DB8CA971": "latest",
    "Mac-E1008331FDC96864": "latest",
    "Mac-5F9802EFE386AA28": "latest",
    "Mac-E7203C0F68AA0004": "latest",
    "Mac-A61BADE1FDAD7B05": "latest",
    "Mac-F22589C8": "10.13.6",
    "Mac-94245B3640C91C81": "10.13.6",
    "Mac-94245A3940C91C80": "10.13.6",
    "Mac-942459F5819B171B": "10.13.6",
    "Mac-4B7AC7E43945597E": "10.15.7",
    "Mac-6F01561E16C75D06": "10.15.7",
    "Mac-F60DEB81FF30ACF6": "12.7.6",
    "Mac-27AD2F918AE68F61": "latest",
    "Mac-F2208EC8": "10.13.6",
    "Mac-8ED6AF5B48C039E1": "10.13.6",
    "Mac-4BC72D62AD45599E": "10.13.6",
    "Mac-7BA5B2794B2CDB12": "10.13.6",
    "Mac-031AEE4D24BFF0B1": "10.15.7",
    "Mac-F65AE981FFA204ED": "10.15.7",
    "Mac-35C5E08120C7EEAF": "12.7.6",
    "Mac-7BA5B2DFE22DDD8C": "latest",
    "Mac-942B5BF58194151B": "10.13.6",
    "Mac-942B59F58194171B": "10.13.6",
    "Mac-00BE6ED71E35EB86": "10.15.7",
    "Mac-FC02E91DDD3FA6A4": "10.15.7",
    "Mac-7DF2A3B5E5D671ED": "10.15.7",
    "Mac-031B6874CF7F642A": "10.15.7",
    "Mac-27ADBB7B4CEE8E61": "10.15.7",
    "Mac-77EB7D7DAF985301": "10.15.7",
    "Mac-81E3E92DD6088272": "11.7.10",
    "Mac-42FD25EABCABB274": "11.7.10",
    "Mac-A369DDC4E67F1C45": "12.7.6",
    "Mac-FFE5EF870D7BA81A": "12.7.6",
    "Mac-DB15BD556843C820": "12.7.6",
    "Mac-65CE76090165799A": "12.7.6",
    "Mac-B809C3757DA9BB8D": "12.7.6",
    "Mac-4B682C642B45593E": "13.7",
    "Mac-77F17D7DA9285301": "13.7",
    "Mac-BE088AF8C5EB4FA2": "13.7",
    "Mac-AA95B1DDAB278B95": "latest",
    "Mac-63001698E7A34814": "latest",
    "Mac-CFF7D910A743CAAF": "latest",
    "Mac-AF89B6D9451A490B": "latest",
    "Mac-7BA5B2D9E42DDD94": "latest"
}

OUTPUT_DIR = "com.apple.recovery.boot"

def gui_main():
    root = tk.Tk()
    root.title("Mac Recovery Image Downloader (Unofficial)")
    root.geometry("920x720")

    style = ttk.Style()
    style.configure("TLabel", padding=6)

    # Input Frame
    input_frame = ttk.LabelFrame(root, text="Input", padding=10)
    input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

    # Board ID and macOS Version Combo Box
    board_id_options = [f"{board_id} ({board_data[board_id]})" for board_id in board_data]

    board_id_label = ttk.Label(input_frame, text="Board ID & macOS Version:")
    board_id_label.grid(row=0, column=0, sticky=tk.W)
    board_id_combo = ttk.Combobox(input_frame, values=board_id_options, state='readonly')
    board_id_combo.grid(row=0, column=1, padx=5, sticky=tk.W)
    board_id_combo['width'] = 50


    # Other input fields
    mlb_label = ttk.Label(input_frame, text="MLB Serial (Optional):")
    mlb_label.grid(row=1, column=0, sticky=tk.W)
    mlb_entry = ttk.Entry(input_frame)
    mlb_entry.grid(row=1, column=1, padx=5, sticky=tk.W)

    os_type_label = ttk.Label(input_frame, text="OS Type:")
    os_type_label.grid(row=2, column=0, sticky=tk.W)
    os_type_combo = ttk.Combobox(input_frame, values=['default', 'latest'], state='readonly')
    os_type_combo.current(0)
    os_type_combo.grid(row=2, column=1, padx=5)

    diag_var = tk.BooleanVar(value=False)
    diag_check = tk.Checkbutton(input_frame, text="Diagnostics Image", variable=diag_var)
    diag_check.grid(row=3, column=0, columnspan=2)

    # Output Frame (Added Log)
    output_frame = ttk.LabelFrame(root, text="Output and Log", padding=10)
    output_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
    log_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD)
    log_text.grid(row=0, column=0, sticky="nsew")
    log_text.config(state=tk.DISABLED)

    # Output Directory Selection
    def browse_directory():
        directory = filedialog.askdirectory()
        if directory:
            outdir_entry.delete(0, tk.END)
            outdir_entry.insert(0, directory)

    outdir_label = ttk.Label(output_frame, text="Output Directory:")
    outdir_label.grid(row=1, column=0, sticky=tk.W)
    outdir_entry = ttk.Entry(output_frame, textvariable=tk.StringVar(value='com.apple.recovery.boot'))
    outdir_entry.grid(row=1, column=1, padx=5)
    browse_button = ttk.Button(output_frame, text="Browse", command=browse_directory)
    browse_button.grid(row=1, column=2, padx=5)

    # Button Frame
    button_frame = ttk.Frame(root, padding=10)
    button_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

    def download_action():
        selected_option = board_id_combo.get()
        if selected_option:
            board_id = selected_option.split(" ")[0]
            args = argparse.Namespace(
                action='download',
                outdir=os.path.join(SELF_DIR, OUTPUT_DIR),  # Use the defined output directory
                basename="Basesystem",  # Fixed basename
                board_id=board_id,
                mlb=mlb_entry.get() or MLB_ZERO,
                os_type=os_type_combo.get(),
                verbose=False,
                diagnostics=diag_var.get()
            )

            # ... (update_progress function remains the same) ...

            download_thread = threading.Thread(target=lambda: action_download(args, update_progress))
            download_thread.start()
        else:
            messagebox.showerror("Error", "Please select a Board ID.")


    download_button = ttk.Button(button_frame, text="Download", command=download_action)
    download_button.grid(row=0, column=0, padx=5)

    root.mainloop()


if __name__ == '__main__':
    gui_main()
