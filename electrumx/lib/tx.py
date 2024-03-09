# Copyright (c) 2016-2021, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# This file is licensed under the Open BSV License version 3, see LICENCE for details.

'''Transaction-related classes and functions.'''

from collections import namedtuple
from electrumx.lib import util
from electrumx.lib.hash import double_sha256, hash_to_hex_str, sha256
from electrumx.lib.util import (
    unpack_le_int32_from, unpack_le_int64_from, unpack_le_uint16_from,
    unpack_le_uint32_from, unpack_le_uint64_from, pack_le_int32, pack_varint,
    pack_le_uint32, pack_le_int64, pack_varbytes,
)

ZERO = bytes(32)
MINUS_1 = 4294967295


class Tx(namedtuple("Tx", "version inputs outputs locktime")):
    '''Class representing a transaction.'''

    def serialize(self):
        return b''.join((
            pack_le_int32(self.version),
            pack_varint(len(self.inputs)),
            b''.join(tx_in.serialize() for tx_in in self.inputs),
            pack_varint(len(self.outputs)),
            b''.join(tx_out.serialize() for tx_out in self.outputs),
            pack_le_uint32(self.locktime)
        ))


class TxInput(namedtuple("TxInput", "prev_hash prev_idx script sequence")):
    '''Class representing a transaction input.'''
    def __str__(self):
        script = self.script.hex()
        prev_hash = hash_to_hex_str(self.prev_hash)
        return ("Input({}, {:d}, script={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, script, self.sequence))

    def is_generation(self):
        '''Test if an input is generation/coinbase like'''
        return self.prev_idx == MINUS_1 and self.prev_hash == ZERO

    def serialize(self):
        return b''.join((
            self.prev_hash,
            pack_le_uint32(self.prev_idx),
            pack_varbytes(self.script),
            pack_le_uint32(self.sequence),
        ))


class TxOutput(namedtuple("TxOutput", "value pk_script")):

    def serialize(self):
        return b''.join((
            pack_le_int64(self.value),
            pack_varbytes(self.pk_script),
        ))


class Deserializer:
    '''Deserializes transactions.

    This code is highly optimised and very performance sensitive.
    '''

    def __init__(self, buf, start=0):
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.view = memoryview(buf)
        self.cursor = start

    def read_tx(self):
        '''Return a deserialized transaction.'''
        tx, self.cursor = read_tx(self.view, self.cursor)
        return tx

    def read_tx_and_hash(self):
        '''Return a (deserialized TX, tx_hash) pair.

        The hash needs to be reversed for human display; for efficiency
        we process it in the natural serialized order.
        '''
        start = self.cursor
        tx, end = read_tx(self.view, self.cursor)
        self.cursor = end
        if tx.version != 10:
            return tx, double_sha256(self.view[start:end])
        else:
            serialization = b''
            T_version = tx.version.to_bytes(4, byteorder='little')
            T_locktime = tx.locktime.to_bytes(4, byteorder='little')
            T_input_count = len(tx.inputs).to_bytes(4, byteorder='little')
            T_output_count = len(tx.outputs).to_bytes(4, byteorder='little')
            # self.logger.info(f'this is my message=========================  T_version :{T_version.hex()}\n')
            # self.logger.info(f'this is my message=========================  T_locktime :{T_locktime.hex()}\n')
            # self.logger.info(f'this is my message=========================  T_input_count :{T_input_count.hex()}\n')
            # self.logger.info(f'this is my message=========================  T_output_count :{T_output_count.hex()}\n')
            serialization_1 = b''
            serialization_2 = b''
            serialization_3 = b''
            for input in tx.inputs:
                T_input_prev_hash = bytes(input.prev_hash)
                T_input_prev_idx = input.prev_idx.to_bytes(4, byteorder='little')
                T_input_sequence = input.sequence.to_bytes(4, byteorder='little')
                serialization_1 = serialization_1 + T_input_prev_hash + T_input_prev_idx + T_input_sequence
                T_input_script = bytes(input.script)
                serialization_2 = serialization_2 + sha256(T_input_script)
                # self.logger.info(f'this is my message=========================  T_input_prev_hash :{T_input_prev_hash.hex()}\n')
                # self.logger.info(f'this is my message=========================  T_input_prev_idx  :{T_input_prev_idx.hex()}\n')
                # self.logger.info(f'this is my message=========================  T_input_sequence :{T_input_sequence.hex()}\n')
                # self.logger.info(f'this is my message=========================  T_input_script :{T_input_script.hex()}\n')
            for output in tx.outputs:
                T_amount = output.value.to_bytes(8, byteorder='little')
                T_output_script = bytes(output.pk_script)
                # self.logger.info(f'this is my message=========================  T_amount :{T_amount.hex()}\n')
                # self.logger.info(f'this is my message=========================  T_output_script :{T_output_script.hex()}\n')
                serialization_3 = serialization_3 + T_amount + sha256(T_output_script)
            serialization = T_version + T_locktime + T_input_count + T_output_count + sha256(serialization_1) + sha256(serialization_2) + sha256(serialization_3)
            # self.logger.info(f'this is my message=========================  serialization1 :{serialization_1.hex()}\n')
            # self.logger.info(f'this is my message=========================  serialization1 hash:{sha256(serialization_1).hex()}\n')
            # self.logger.info(f'this is my message=========================  serialization2 :{serialization_2.hex()}\n')
            # self.logger.info(f'this is my message=========================  serialization2 hash:{sha256(serialization_2).hex()}\n')
            # self.logger.info(f'this is my message=========================  serialization3 :{serialization_3.hex()}\n')
            # self.logger.info(f'this is my message=========================  serialization3 hash:{sha256(serialization_3).hex()}\n')
            # self.logger.info(f'this is my message=========================  serialization :{serialization.hex()}\n')
            # self.logger.info(f'this is my message=========================  result :{double_sha256(serialization).hex()}\n')
            return tx, double_sha256(serialization)
    def read_varint(self):
        value, self.cursor = read_varint(self.view, self.cursor)
        return value


def read_varint(buf, cursor):
    n = buf[cursor]
    cursor += 1
    if n < 253:
        return n, cursor
    if n == 253:
        return read_le_uint16(buf, cursor)
    if n == 254:
        return read_le_uint32(buf, cursor)
    return read_le_uint64(buf, cursor)


def read_varbytes(buf, cursor):
    size, cursor = read_varint(buf, cursor)
    end = cursor + size
    return buf[cursor: end], end


def read_le_uint16(buf, cursor):
    result, = unpack_le_uint16_from(buf, cursor)
    return result, cursor + 2


def read_le_uint32(buf, cursor):
    result, = unpack_le_uint32_from(buf, cursor)
    return result, cursor + 4


def read_le_uint64(buf, cursor):
    result, = unpack_le_uint64_from(buf, cursor)
    return result, cursor + 8


def read_le_int32(buf, cursor):
    result, = unpack_le_int32_from(buf, cursor)
    return result, cursor + 4


def read_le_int64(buf, cursor):
    result, = unpack_le_int64_from(buf, cursor)
    return result, cursor + 8


def read_input(buf, cursor):
    start = cursor
    cursor += 32
    prev_hash = buf[start: cursor]
    prev_idx, cursor = read_le_uint32(buf, cursor)
    script, cursor = read_varbytes(buf, cursor)
    sequence, cursor = read_le_uint32(buf, cursor)

    return TxInput(prev_hash, prev_idx, script, sequence), cursor


def read_output(buf, cursor):
    value, cursor = read_le_int64(buf, cursor)
    pk_script, cursor = read_varbytes(buf, cursor)
    return TxOutput(value, pk_script), cursor


def read_many(buf, cursor, reader):
    count, cursor = read_varint(buf, cursor)

    items = []
    append = items.append
    for _ in range(count):
        item, cursor = reader(buf, cursor)
        append(item)

    return items, cursor


def read_tx(buf, cursor):
    '''Deserialize a transaction from a buffer.  Return a (tx, cursor) pair.

    If the buffer does not hold the whole transaction, raises struct.error or IndexError.
    '''
    version, cursor = read_le_int32(buf, cursor)
    inputs, cursor = read_many(buf, cursor, read_input)
    outputs, cursor = read_many(buf, cursor, read_output)
    locktime, cursor = read_le_uint32(buf, cursor)

    return Tx(version, inputs, outputs, locktime), cursor
