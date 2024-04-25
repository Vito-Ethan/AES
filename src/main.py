import timeit

from ecb import test_ecb
from rsa import *
from cbc import *
from ofb import test_ofb
from ctr import test_ctr
from cfb import test_cfb

if __name__ == '__main__':
    test_ecb()
    test_cbc()
    test_ofb()
    test_cfb()
    test_ctr()

    # aes_exec_times = timeit.timeit(test_eax, number=500)
    # print(f"\nAVG AES execution time: {aes_exec_times / 500}s")
    # rsa_exec_times = timeit.timeit(test_rsa, number=500)
    # print(f"AVG RSA execution time: {rsa_exec_times / 500}s")
