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
        default=None,
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


class CodeFile(object):
    Preamble = '# '
    Marker_Hash = 'Hash: '
    Marker_Version = 'Version: '
    Marker_Begin_Message = '-----BEGIN PGP SIGNED MESSAGE-----'
    Marker_Begin_Signature = '-----BEGIN PGP SIGNATURE-----'
    Marker_End_Signature = '-----END PGP SIGNATURE-----'

    @staticmethod
    def has_shebang(line):
        """
        Checks if the line contains a shebang.
        """
        return line.startswith('#!')

    @staticmethod
    def has_encoding(line):
        """
        Looks for a PEP 0263 compatible encoding line.
        """
        return (
            line.startswith("#") and
            re.search("coding[:=]\s*([-\w.]+)", line) is not None
        )

    def __init__(self, content, shebang=None, encoding=None):
        self.content = content
        self.shebang = shebang
        self.encoding = encoding
        self.gpg = gnupg.GPG()
        self.set_keyid(None)
        self.set_signature(signature=None, version=None, hash=None)

    def set_signature(self, signature, version, hash):
        self.version = version
        self.sig_data = signature
        self.hash = hash
        return self

    def set_keyid(self, keyid):
        self.keyid = keyid
        return self

    def has_signature(self):
        """
        Returns true if a signature is present.
        This does NOT validate the signature.
        """
        return (self.signature is not None and
                self.version is not None and
                self.hash is not None)

    def is_valid(self):
        """
        Checks weither the signature is valid.
        """

    @staticmethod
    def read(filename):
        """
        Read the contents of a file.
        Extracts shebang, encoding line and if existant the signature
        """
        lines = []
        signature = []
        env = {
            'shebang': None,
            'coding': None,
            'hash': "SHA256",
            'version': "",
        }
        fsm = {
            "init": (lambda l: None, [
                (lambda l: l.startswith("#!"), "shebang"),
                (lambda l: "coding:" in l, "coding"),
                (lambda l: l == CodeFile.Preamble + CodeFile.Marker_Begin_Message, "pgp_message"),
                (lambda l: True, "content"),
            ]),
            "shebang": (lambda l: env.update(shebang=l), [
                (lambda l: "coding:" in l, "coding"),
                (lambda l: l == CodeFile.Preamble + CodeFile.Marker_Begin_Message, "pgp_message"),
                (lambda l: True, "content"),
            ]),
            "coding": (lambda l: env.update(coding=l), [
                (lambda l: l == CodeFile.Preamble + CodeFile.Marker_Begin_Message, "pgp_message"),
                (lambda l: True, "content"),
            ]),
            "content": (lambda l: lines.append(l), [
                (lambda l: l == CodeFile.Preamble + CodeFile.Marker_Begin_Signature, "pgp_signature"),
                (lambda l: True, "content"),
            ]),
            "pgp_message": (lambda l: None, [
                (lambda l: l.startswith(CodeFile.Preamble + CodeFile.Marker_Hash), "pgp_hash"),
                (lambda l: True, "error"),
            ]),
            "pgp_hash": (lambda l: env.update(hash=l[len(CodeFile.Preamble + CodeFile.Marker_Hash):]), [
                (lambda l: True, "content"),
            ]),
            "pgp_signature": (lambda l: None, [
                (lambda l: l.startswith(CodeFile.Preamble + CodeFile.Marker_Version), "pgp_version"),
                (lambda l: True, "error"),
            ]),
            "pgp_version": (lambda l: env.update(version=l[len(CodeFile.Preamble + CodeFile.Marker_Version):]), [
                (lambda l: True, "pgp_sig_data"),
            ]),
            "pgp_sig_data": (lambda l: signature.append(l[len(CodeFile.Preamble):]), [
                (lambda l: l == CodeFile.Preamble + CodeFile.Marker_End_Signature, "pgp_end_sig"),
                (lambda l: True, "pgp_sig_data"),
            ]),
            "pgp_end_sig": (lambda l: None, [
                (lambda l: True, "eof"),
            ]),
            "eof": (lambda l: None, [
                (lambda l: True, "error"),
            ]),
        }
        state = "init"
        last = ""
        with open(filename, "r") as fHnd:
            for line in fHnd:
                line = line.rstrip()
                handler, transitions = fsm[state]
                for condition, next_state in transitions:
                    if condition(line):
                        state = next_state
                        break
                handler(last)
                last = line
        file = CodeFile(lines, env['shebang'], env['coding'])
        file.set_signature(signature, env['version'], env['hash'])
        return file

    @property
    def head(self):
        return (CodeFile.Marker_Begin_Message + "\n" +
                CodeFile.Marker_Hash + self.hash + "\n")

    @property
    def text(self):
        return "\n".join(map(lambda s: s.rstrip(), self.content))+"\n"

    @property
    def signature(self):
        return (CodeFile.Marker_Begin_Signature + "\n" +
                CodeFile.Marker_Version + self.version + "\n" +
                "\n" +
                "\n".join(self.sig_data) + "\n" +
                CodeFile.Marker_End_Signature + "\n")

    def prepend_preamble(self, text):
        return "\n".join([
                self.Preamble + line for line in text.splitlines()
            ]) + "\n"

    def write(self, filename):
        with open(filename, "wb") as fHnd:
            if self.shebang is not None:
                fHnd.write(self.shebang + "\n")
            if self.encoding is not None:
                fHnd.write(self.encoding + "\n")
            fHnd.write(self.prepend_preamble(self.head))
            fHnd.write(self.text)
            fHnd.write(self.prepend_preamble(self.signature))

    def generate_signature(self, keyid=None):
        # FIXME Replace asserts with exceptions
        if keyid is not None:
            self.set_keyid(keyid)
        signed = self.gpg.sign(self.text, keyid=self.keyid)
        signature_lines = map(str.rstrip, str(signed).splitlines())
        marker_file = signature_lines.pop(0)
        assert marker_file == CodeFile.Marker_Begin_Message, marker_file
        hash_line = signature_lines.pop(0)
        assert hash_line.startswith(CodeFile.Marker_Hash), hash_line
        hash_algo = hash_line[len(CodeFile.Marker_Hash):]
        # Skip over the content
        while signature_lines[0].rstrip() != CodeFile.Marker_Begin_Signature:
            signature_lines.pop(0)
        marker_begin = signature_lines.pop(0)
        assert marker_begin == CodeFile.Marker_Begin_Signature, marker_begin
        version_line = signature_lines.pop(0)
        assert version_line.startswith(CodeFile.Marker_Version), version_line
        version = version_line[len(CodeFile.Marker_Version):]
        empty = signature_lines.pop(0)
        assert len(empty) == 0
        marker_end = signature_lines.pop()
        assert marker_end == CodeFile.Marker_End_Signature, marker_end
        self.set_signature(signature_lines, version=version, hash=hash_algo)
        return self

    def verify(self):
        content = self.head + "\n" + self.text + self.signature
        return self.gpg.verify(content)


def main():
    args = get_arguments()
    action = args['action']
    key = args['key']
    files = args['file']
    for filename in files:
        file = CodeFile.read(filename)
        print "{}:".format(filename),
        if action == 'sign':
            file.generate_signature(key)
            assert file.has_signature()
            verify = file.verify()
            if verify.valid:
                print "Signed by {}".format(verify.username)
                file.write(filename)
            else:
                print "Could not be verified after signing"
        elif action == "verify":
            verify = file.verify()
            if verify.valid:
                print "Valid signature by {}".format(verify.username)
            elif verify.username is not None:
                print "Invalid signature by {}".format(verify.username)
            else:
                print "Could not be verified"


if __name__ == "__main__":
    main()
# -----BEGIN PGP SIGNATURE-----
# Version: GnuPG v2
# 
# iQIcBAEBCAAGBQJVrsG3AAoJEBajiJpINLdMvs8QALGbuoihesly0fVo1Ib8UTmY
# iCojrftQRbHnCSqsogRZaZoz1ELiLTgG+aPW4+l3JEJhZ2oBJsXvcGtC56a66Hg+
# kAouX2233izp78jYFKLwfIBK5O2B7Kzwb4NZB1qgdFPOst318G7uIPz6VbACbEzb
# RdLzdeFpocaGw+2eyWmADqdmHPij5RB+E5Ra9/gL0YjpvS9Vzqr/PDEIAr/EocmU
# GHOknUul9Pqp7fBoLhvce+v9hYYTNi/1gtWnbsydmNGKPcP+x+UihnkXCLeDIVge
# Z+1Yrg1uM5J0JQ1+J6kFZoHiTk/0fK2ElNMLTRh/l+I/a+Y7YKDcaKSRopj/pv/0
# MOeAm8qXOKxaHiVL0cbL7T0l4I0y8upH6shyrv5n35vpv/eU3qI2KPjXRB7/J5nt
# MOXG5IEgrAwbdueIqXKZxuPd+dRQshwnEYGFJt2YoQsQp6syT+quO7t1lmc0VMDz
# NGU0EY76zZc6suv83RzTWmmI/mJYe+sLDwsyJkEn0eKKYyMoimDYIFiTIozxLhWQ
# oAPJhb2ujuxwXTQefX8RCduUx5sBgEX6bEsinL1jjz1PFm7ZQF4tFmXaO7bQBOEz
# QskIC0Rx4MuqA0av2QwxmAIOoHssKiLhB8YyVzDQ7BejtZgp4G6JAdoYVOchPkqY
# DizGE/Dp4pyfhx0V04F0
# =6mOt
# -----END PGP SIGNATURE-----
