#!/usr/bin/env python3

import sys
import string

# Append path of py-evm repo for imports
from eth_keys.datatypes import PrivateKey

sys.path.append('./src/py-evm/')
sys.path.append('./src/py-evm/tests/')


from evm.db.backends.memory import MemoryDB
from eth_keys import keys
from eth_utils import (
    decode_hex,
    to_wei,
)
from evm.vm.computation import (
    BaseComputation
)

from conftest import (
    chain_without_block_validation
)

ADDRESS = bytes.fromhex("123456789A123456789A123456789A123456789A")
GAS_PRICE = 1


def base_db() -> MemoryDB:
    return MemoryDB()


def funded_address_private_key() -> PrivateKey:
    return keys.PrivateKey(
        decode_hex('0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8')
    )


def funded_address() -> bytes:
    return funded_address_private_key().public_key.to_canonical_address()


def funded_address_initial_balance():
    return to_wei(1000, 'ether')


class Simulator(object):

    def __init__(self):
        self.chain = chain_without_block_validation(base_db(), funded_address(), funded_address_initial_balance())
        self.vm = self.chain.get_vm()

    def executeCode(self, gas, data, code) -> BaseComputation:
        """
        Executes the given bytecode sequence

        :param gas:
        :param data:
        :param code:
        :return:
        """
        origin = None
        value = 10

        return self.vm.execute_bytecode(origin, GAS_PRICE, gas, ADDRESS, ADDRESS, value, data, code)


def main() -> None:
    inputCode = sys.argv[1]
    print("Code: " + sys.argv[1])

    sim = Simulator()

    # execute raw bytecode
    computation = sim.executeCode(1000, b'', decode_hex(inputCode))

    print("Gas used: " + str(computation.get_gas_used()))
    print("Remaining gas: " + str(computation.get_gas_remaining()))

    print(computation.get_log_entries())
    print("Stack: " + str(computation._stack.values))


if __name__ == '__main__':
    main()
