# psygnature
Python code signing using pgp.

Since I was unable to find any packages that allowed signing the code
in place, I decided to write my own little wrapper around gpg.
The idea is to embed standard gpg signatures inside a python file using
comments. This way the integrity and origin of the file and the can be
verified.

This tool reads a file, omitting the optional shebang and encoding-hint
lines, and passes the rest directly to GPG. If a signature is already
present it gets extracted.
Since the file is signed "as-is", this can also be done by hand by
removing the "#" symbol and leading spaces around the ascii-armor.
