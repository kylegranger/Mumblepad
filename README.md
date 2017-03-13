# Mumblepad

Mumblepad Block Cipher
Version 1, completed March 13, 2017

[ Full-on 12-page PDF almost done, which fully describes the block cipher! ]

A symmetric-key block cipher, with a key size 4096 bytes, 32768 bits.
Six different block sizes (static, mutually exclusive): 128, 256, 512, 1024, 2048, 4096 bytes.

Encryption and decryption, runs on either CPU of GPU with OpenGL
May run multi-threaded on CPU.
Runs on GPU with OpenGL or OpenGL ES 2.0.

Encrypted blocks containing same plaintext are different, due to
small amount of per-block random number padding.
Encrypted block also contains length, 16-bit sequence number, 32-bit checksum.
Resulting plaintext is 87.5% to 97.65% of total block size, depending on size.
With no block cipher mode, may use parallel processing, multi-threaded encrypt/decrypt.
The multi-threaded implementation can encrypt or decrypt 210MB per second on an HP ZBook 17 (Gen1).

8 rounds, 2 passes (diffuse, confuse) per round.

Full source code to library, which contains four different implementations:
   single-threaded CPU
   multi-threaded CPU
   single-block GPU
   multi-block GPU

Demo/test program included, which links to library.  Detailed PDF to come in a day or so.

VS 2015 Express solutions/projects.

Reference encrypted files are also included, along with key used and the original plaintext files.

Each implementation may decrypt data from a different implementation, as long 
as same key and block size.


Free for non-commercial use, or analysis/evaluation -- still a bit of a work-in-progress.



