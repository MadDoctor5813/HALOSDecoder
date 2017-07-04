# HALOSDecoder
A way to automatically test keys, IV's and One Time Pads for the [752 Hex Code.](http://thepizzaisalie.wikia.com/wiki/752_Hex_Code)

# Instructions
The program comes with four files: HALOS.txt, KEYS.txt, IVS.txt, and PADS.txt.  
HALOS.txt contains the HALOS data in text form. If you want to manipulate the data somehow before decrypting, do it there. 
KEYS, IVS, and PADS contain keys, IVs and pads, one per line. Keys must be 16, 24, or 32 characters long. 
IVs must be 16 characters long.
Pads must be 376 characters long, to match the size of the HALOS data.
On running the program, the program will try the raw data with every key and every supported algorithm in Electronic Codebook Mode, 
and then try again in Cipher Block Chaining mode, using the supplied IV's. 
It will then try using the raw data xored with the pad, and then try the raw data added to the pad modulo 256, again with every key and algorithm.

Currently the program supports AES, Rijndael, Serpent, and Twofish (the algorithms listed by Storm in his messages)

After running the program will close without any console output. This is normal. It will leave behind two files, log.txt and log_full.txt.
log_full.txt will have the contents of every decryption run, including the algorithm and key used, the plaintext, and the frequency analysis of the output.
Most of these will be useless, so when a plaintext is produced with less than 180 distinct bytes, it is marked as interesting and sent to log.txt. 
