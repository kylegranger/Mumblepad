# Mumblepad

Mumblepad Block Cipher
Version 1, completed March 14, 2017
Created by Kyle Granger

A symmetric-key block cipher, with a key size 4096 bytes, 32768 bits.

The main features of Mumblepad are:
- a relatively large 4096-byte key.
- padding of plaintext blocks with random number bytes, enabling completely
  different encrypted blocks containing same plaintext.
- no requirement of a block cipher mode, thus parallelizable.
- implementation on GPU, in addition to CPU.
- may work with 6 different block sizes, ranging from 128 to 4096 bytes.
- the multi-threaded implementation encrypts or decrypts @ 210MB/s on laptop.

Detailed description in 13-page PDF in docs directory: mumblepad_specification_v1.pdf

Six different block sizes (static, mutually exclusive): 128, 256, 512, 1024, 2048, 4096 bytes.
Encryption and decryption, runs on either CPU or GPU, may run multi-threaded on CPU.
Runs on GPU with OpenGL or OpenGL ES 2.0; encryption and decryption operations implemented in fragment shaders.
Encrypted blocks containing same plaintext are different, due to small amount of per-block random number padding.
Encrypted block also contains 16-bit length, 16-bit sequence number, 32-bit checksum.
Resulting plaintext is 87.5% to 97.65% of total block size, depending on size.
With no block cipher mode, may use parallel processing, multi-threaded encrypt/decrypt.
The multi-threaded implementation can encrypt or decrypt 210MB per second on an HP ZBook 17 (Gen1).
8 rounds, 2 passes (diffuse, confuse) per round.

Full source code to library, which contains four different implementations:
   single-threaded CPU,
   multi-threaded CPU,
   single-block GPU,
   multi-block GPU


Demo/test program included, which links to library; Visual Studio Express 2015 solutions/projects.

Reference encrypted files are also included, along with key used and the original plaintext files.

Each of the four implementations may decrypt data from a different implementation, as long 
as same key and block size.


Free for non-commercial use, or analysis/evaluation -- still a bit of a work-in-progress.

Contact:  kyle.granger@chello.at



