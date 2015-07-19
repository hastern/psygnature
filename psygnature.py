#!/usr/bin/env python
# -*- coding:utf-8 -*-
# -----BEGIN PGP SIGNED MESSAGE-----
# Hash: SHA256
#
# Author: Hanno Sternberg <hanno@almostintelligent.de>
# GPG based code signing for python scripts.
#

import re
import sys
import argparse
import logging

import gnupg

logger = logging.getLogger("psygnature")


def get_arguments():
    """
    Create argument parser and parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="psygnature - GPG base code signing for python scripts"
    )
    parser.add_argument(
        "action",
        type=str,
        choices=("sign", "verify"),
        help="Select the appropriate actions."
    )
    parser.add_argument(
        "--key",
        type=str,
        default = None,
        help="The ID of the key used for signing the code."
    )
    parser.add_argument(
        "file",
        type=str,
        nargs="+",
        help="One or more files to either sign or verify."
    )

    args = parser.parse_args()
    return vars(args)

Mode_Preface = 0
Mode_Content = 1
Mode_Hash = 2
Mode_Signature = 3
Mode_End = 4

Marker_Hash = '# Hash: '
Marker_Begin_Message = '# -----BEGIN PGP SIGNED MESSAGE-----'
Marker_Begin_Signature = '# -----BEGIN PGP SIGNATURE-----'
Marker_End_Signature = '# -----END PGP SIGNATURE-----'

def has_shebang(line):
    """
    Checks if the line contains a shebang.
    """
    return line.startswith('#!')


def has_encoding(line):
    """
    Looks for a PEP 0263 compatible encoding line.
    """
    return (
        line.startswith("#") and
        re.search("coding[:=]\s*([-\w.]+)", line) is not None
    )


def read_file_contents(filename):
    """
    Read the contents of a file.
    Extracts shebang, encoding line and if existant the signature
    """
    lines = []
    signature = []
    shebang = ""
    coding = ""
    hash = "SHA256"
    mode = Mode_Content
    with open(filename, "r") as fHnd:
        first = fHnd.readline().rstrip()
        second = fHnd.readline().rstrip()
        if has_shebang(first):
            shebang = first
            if has_encoding(second):
                coding = second
            else:
                lines.append(second)
        elif has_encoding(first):
            coding = first
            lines.append(second)
        else:
            lines.append(first)
            lines.append(second)
        for line in fHnd:
            # Remove linebreak to avoid EOL dependent problems.
            line = line.rstrip()
            if line == Marker_Begin_Message:
                # TODO: Validate that this state is only entered when
                # mode is Preface.
                mode = Mode_Hash
                print "FOUND MESSAGE MARKER"
            elif line == Marker_Begin_Signature:
                # TODO: Validate that this state is only entered when
                # mode is Content
                mode = Mode_Signature
                print "FOUND SIGNATURE START"
            elif line == Marker_End_Signature:
                # TODO: Validate that this state is only entered when
                # mode is Signature.
                mode = Mode_End
                print "FOUND SIGNATURE END"
            elif mode == Mode_Hash and line.startswith(Marker_Hash):
                hash = line[len(Marker_Hash):]
                mode = Mode_Content
                print "USING HASH:", hash
            elif mode in (Mode_Preface, Mode_Content):
                lines.append(line.rstrip())
            elif mode == Mode_Signature:
                # Don't read the first two characters ( -> "# ")
                signature.append(line[2:])
            elif mode == Mode_End:
                # TODO: Show an Error if there is content after the
                # end line.
                pass
    return shebang, coding, hash, lines, signature


def lines_to_text(lines):
    return "\n".join(map(lambda s: s.rstrip() , lines))+"\n"


def write_file(filename, shebang, coding, hash_algo, lines, signature):
    with open(filename, "wb") as fHnd:
        if shebang != "":
            fHnd.write(shebang + "\n")
        if coding != "":
            fHnd.write(coding + "\n")
        fHnd.write(Marker_Begin_Message + "\n")
        fHnd.write(Marker_Hash + hash_algo + "\n")
        fHnd.write(lines_to_text(lines))
        fHnd.write("\n".join(prepare_signature(signature)))
        fHnd.write("\n")


def generate_signature(gpg, lines, key):
    text = lines_to_text(lines)
    signed = gpg.sign(text, keyid=key)
    signature_lines = str(signed).splitlines()
    while signature_lines[0].rstrip() != Marker_Begin_Signature[2:]:
        signature_lines.pop(0)
    return lines_to_text(signature_lines)


def prepare_signature(sig):
    return map(lambda s: '# '+s, str(sig).splitlines())


def verify_signature(gpg, lines, hash_algo, signature):
    head = Marker_Begin_Message[2:]+"\nHash: {}\n\n".format(hash_algo)
    text = lines_to_text(lines)
    if isinstance(signature, list):
        sig = Marker_Begin_Signature[2:]+"\n" + lines_to_text(signature) + Marker_End_Signature[2:]+"\n"
    else:
        sig = str(signature)
    content = head+text+sig
    return gpg.verify(content)


def main():
    args = get_arguments()
    action = args['action']
    key = args['key']
    files = args['file']
    gpg = gnupg.GPG()
    for file in files:
        shebang, coding, hash_algo, lines, signature = read_file_contents(file)
        if action == 'sign':
            signature = generate_signature(gpg, lines, key)
            verify = verify_signature(gpg, lines, hash_algo, signature)
            print file, verify.valid, verify.username, verify.key_id, verify.stderr
            write_file(file, shebang, coding, hash_algo, lines, signature)
        elif action == "verify":
            verify = verify_signature(gpg, lines, hash_algo, signature)
            print file, verify.valid, verify.username, verify.key_id, verify.stderr


if __name__ == "__main__":
    main()
# -----BEGIN PGP SIGNATURE-----
# Version: GnuPG v2
#
# iQIcBAEBCAAGBQJVrBohAAoJEBajiJpINLdMbbcQAJtE2nen53dMiw6HPR18fetT
# +1Ng+ISk+vEhljYwltHcv9IaGpW/Z7NpUjLqjaVunJ5bl0VDynV8pdzo2nkUW9ab
# jeTcrC+i778YqiZLHy6/2UUafI8IdHq5MIRL5tWkfnhwY85vVeoTfcRW+bqcop+w
# 6QnbBr99DLrNuzD38hTo+L7yDZDy7UUFk/FotsxeY4nqzYEcN9cqchtmxWyHf58u
# Nh+R1aVL/uYO4ffnSWZYanJz1mYuXCOfWIBQymdn5DhIOjff4WMW3m7u/b2z8yd/
# MOjO2+bj/wTem3vBsqdoAKeT7AeN3cW/moNS43czZlPPzqMGqGM3eSB8ebbCeNpP
# q0YPfjnCqYbcoJlfOkymR/13M6a7QGpL7515z36Xnb+t65Ckd/75ufYxHp3i/p3L
# G/FEQ7v78q+HMJdSxV8vmVBNaeMnyosO4AOx6e/DjEcSEyDTe70bD3e4YP1QFeIi
# utviHPSwsy4+U0wdxPfs7ghdzkDMJLTFS9CLcnsiBD32msR1uIvIFBb9MldJKvAv
# AEwIwfliYLBQ173wXi4CZs3kdAEXXQA8ea1H3CTiUHsWGIlMD0QfyPJ2VR94Tntm
# rUIzt5p3oz+h4BN5gztld1IeSkWXh8KltDuN064UxotXyZL9+u6lGqFpqxbunA2S
# zXlH/vLfkT6vAUdEO5/9
# =Ysm6
# -----END PGP SIGNATURE-----
