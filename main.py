#!/usr/bin/env python3

import sys

# Append path of py-evm repo for imports
from datatypes.taintedbytes import tbytes
from eth.db.backends.memory import MemoryDB
from eth.utils.hexadecimal import decode_hex
from eth.vm.computation import BaseComputation
from eth_keys import KeyAPI
from eth_keys.datatypes import PrivateKey
from eth_utils import (
    to_wei,
    to_canonical_address
)
from eth import constants, Chain
from eth.vm.forks.byzantium import ByzantiumVM

sys.path.append('./src/py-evm/')
sys.path.append('./src/py-evm/tests/')


ADDRESS = bytes.fromhex("123456789A123456789A123456789A123456789A")
GAS_PRICE = 1
VERBOSE = False


def base_db() -> MemoryDB:
    return MemoryDB()


lazy_key_api = KeyAPI(backend=None)


def funded_address_private_key() -> PrivateKey:
    return lazy_key_api.PrivateKey(
        decode_hex('0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8')
    )


def funded_address() -> bytes:
    return funded_address_private_key().public_key.to_canonical_address()


def funded_address_initial_balance():
    return to_wei(1000, 'ether')


class ChainHelper(object):

    def chain_with_block_validation(self, base_db, funded_address, funded_address_initial_balance):
        """
        Return a Chain object containing just the genesis block.

        The Chain's state includes one funded account, which can be found in the
        funded_address in the chain itself.

        This Chain will perform all validations when importing new blocks, so only
        valid and finalized blocks can be used with it. If you want to test
        importing arbitrarily constructe, not finalized blocks, use the
        chain_without_block_validation fixture instead.
        """
        genesis_params = {
            "bloom": 0,
            "coinbase": to_canonical_address("8888f1f195afa192cfee860698584c030f4c9db1"),
            "difficulty": 131072,
            "extra_data": b"B",
            "gas_limit": 3141592,
            "gas_used": 0,
            "mix_hash": decode_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),  # noqa: E501
            "nonce": decode_hex("0102030405060708"),
            "block_number": 0,
            "parent_hash": decode_hex("0000000000000000000000000000000000000000000000000000000000000000"),  # noqa: E501
            "receipt_root": decode_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),  # noqa: E501
            "timestamp": 1422494849,
            "transaction_root": decode_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),  # noqa: E501
            "uncles_hash": decode_hex("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")  # noqa: E501
        }
        genesis_state = {
            funded_address: {
                "balance": funded_address_initial_balance,
                "nonce": 0,
                "code": b"",
                "storage": {}
            }
        }
        klass = Chain.configure(
            __name__='TestChain',
            vm_configuration=(
                (constants.GENESIS_BLOCK_NUMBER, ByzantiumVM),
            ),
            network_id=1337,
        )
        chain = klass.from_genesis(base_db, genesis_params, genesis_state)
        return chain

    def import_block_without_validation(chain, block):
        return super(type(chain), chain).import_block(block, perform_validation=False)

    def chain_without_block_validation(
            self,
            request,
            base_db,
            funded_address,
            funded_address_initial_balance):
        """
        Return a Chain object containing just the genesis block.

        This Chain does not perform any validation when importing new blocks.

        The Chain's state includes one funded account and a private key for it,
        which can be found in the funded_address and private_keys variables in the
        chain itself.
        """
        # Disable block validation so that we don't need to construct finalized blocks.
        overrides = {
            'import_block': self.import_block_without_validation,
            'validate_block': lambda self, block: None,
        }

        byzantiumVMForTesting = ByzantiumVM.configure(validate_seal=lambda block: None)
        chain_class = request.param
        klass = chain_class.configure(
            __name__='TestChainWithoutBlockValidation',
            vm_configuration=(
                (constants.GENESIS_BLOCK_NUMBER, byzantiumVMForTesting),
            ),
            **overrides,
        )
        genesis_params = {
            'block_number': constants.GENESIS_BLOCK_NUMBER,
            'difficulty': constants.GENESIS_DIFFICULTY,
            'gas_limit': constants.GENESIS_GAS_LIMIT,
            'parent_hash': constants.GENESIS_PARENT_HASH,
            'coinbase': constants.GENESIS_COINBASE,
            'nonce': constants.GENESIS_NONCE,
            'mix_hash': constants.GENESIS_MIX_HASH,
            'extra_data': constants.GENESIS_EXTRA_DATA,
            'timestamp': 1501851927,
        }
        genesis_state = {
            funded_address: {
                'balance': funded_address_initial_balance,
                'nonce': 0,
                'code': b'',
                'storage': {},
            }
        }
        chain = klass.from_genesis(base_db, genesis_params, genesis_state)
        return chain


class Simulator(object):

    def __init__(self):
        self.chain = ChainHelper().chain_with_block_validation(base_db(),
                                                               funded_address(),
                                                               funded_address_initial_balance())
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


def main(inputCode) -> None:

    print("Code: " + inputCode)

    # create simulator for VM
    sim = Simulator()
    # convert cli string input to tbytes input
    inputAsBytes = tbytes(decode_hex(inputCode))

    if VERBOSE:
        print(" --------types-------------")
        print(type(inputCode))
        print(type(decode_hex(inputCode)))
        print(type(tbytes(decode_hex(inputCode))))
        print(type(inputAsBytes))
        print(" --------types-------------")

    # execute raw bytecode
    computation = sim.executeCode(1000000000000, b'', inputAsBytes)

    if VERBOSE:
        print("Gas used: " + str(computation.get_gas_used()))
        print("Remaining gas: " + str(computation.get_gas_remaining()))

        print(computation.get_log_entries())
        print("Stack: " + str(computation._stack.values))


if __name__ == '__main__':
    main(sys.argv[1])
