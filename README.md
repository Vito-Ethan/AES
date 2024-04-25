# Description
A python implementation of the Advanced Encryption Standard (AES) and 5 of its modes. This project uses
the pycryptodome library for the base implementation of AES.
- The 5 modes built with this library include ECB, CBC, CFB, CTR and CFB.
- There is a helper module under src/util.py which contains several custom made bitwise functions for padding inputs and manipulating byte objects for example.

## Read about it
There is a pdf file (writeup.pdf) which contains a write up of the entire project and the AES modes. You can view all the inputs and outputs for each of the modes with pictures in the pdf.
- All modes were implemented using the diagrams from this website https://xilinx.github.io/Vitis_Libraries/security/2021.2/guide_L1/internals/cfb.html
