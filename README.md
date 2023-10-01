# CMS Parsing

Some short scripts I wrote to extract and parse the CMS blob of an iOS binary. The easiest way to use is by running:
```sh
gcc main.c -o parser
python3 extractCMS.py <binary>
./parser <binary>_CMSBlob
```

It will output useful information about the superblob, as well as each individual blob in the signature. It offers additional, more detailed information about the CodeDirectory blob, and automatically extracts the signature blob from the binary.