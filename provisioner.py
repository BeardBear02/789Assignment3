#!/usr/bin/env python3
import logging
import random
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from toolbox import *

algorithm = b'\x00'
oob_public_key = b'\x00' # No oob public key
authentication_method = b'\x02' # Output oob is used
authentication_action = b'\x04' # Display string

NetworkKey = b'\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00'
KeyIndex = b'\x00\x00'
Flags = b'\x00'
IVIndex = b'\x11\x22\x33\x44'
UnicastAddress = b'\xaa\xbb'

# Create and configure logger
logger = logging.getLogger('provisioner')
logger.setLevel(logging.DEBUG)  # Logger level

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(console_handler)

def start_outputOOB_provisioning(conn):
    try:
        # TODO 1. Receive Beacon
        beacon_message = conn.recv(64)
        logger.info(f'Received Beacon Message: {beacon_message.hex()}')
        if beacon_message[0:1] != BEACON_TYPE:
            raise Exception("Invalid Beacon Message")
        DeviceUUID = beacon_message[1:17]


        # TODO 2. Send link open message
        link_open_message = LINK_OPEN_OPCODE + DeviceUUID
        conn.send(link_open_message)
        logger.info(f'Sent Link Open Message: {link_open_message.hex()}')

        # TODO 3. Receive Link Ack Message
        link_ack_message = conn.recv(64)
        if link_ack_message[0:1] != LINK_ACK_OPCODE:
            raise Exception("Invalid Link Ack Message")
        logger.info(f'Received Link Ack Message: {link_ack_message.hex()}')

        # TODO 4. Provisioning starts
        # Implement the provisioning process here
        # Send Provsioning Invite
        provisioning_invite = PROVISIONING_INVITE_OPCODE + attention_duration
        conn.send(provisioning_invite)
        logger.info(f'Sent Provisioning Invite Message: {provisioning_invite.hex()}')

        # Recieved Provisioning Capabilities
        provisioning_capabilities = conn.recv(64)
        if provisioning_capabilities[0:1] != PROVISIONING_CAPABILITIES_OPCODE:
            raise Exception("Invalid Provisioning Capabilities Message")
        logger.info(f'Received Provisioning Capabilities Message: {provisioning_capabilities.hex()}')

        # Send Provisioning Start
        provisioning_start = (
            PROVISIONING_START_OPCODE +
            algorithm +
            oob_public_key +
            authentication_method +
            authentication_action +
            p8(0x08)
        )
        conn.send(provisioning_start)
        logger.info(f'Sent Provisioning Start Message: {provisioning_start.hex()}')

        # Generate Key Pair and Send to Device
        private_key, public_key_x, public_key_y = generate_key_pair()
        public_key_message = PROVISIONING_PUBLIC_KEY_OPCODE + public_key_x + public_key_y
        conn.send(public_key_message)
        logger.info(f'Sent Provisioner Public Key: {public_key_message.hex()}')

        # Recieve key from device
        device_public_key_message = conn.recv(1024)
        if device_public_key_message[0:1] != PROVISIONING_PUBLIC_KEY_OPCODE:
            logger.error("Invalid opcode received! Expected provisioning public key message.")
            raise ValueError("Received message with invalid opcode.")
        device_public_key_x = device_public_key_message[1:33]
        device_public_key_y = device_public_key_message[33:65]
        logger.info(f'Received Device Public Key: {device_public_key_message.hex()}')

        # Derive DHKey
        ECDHSecret = derive_dhkey(private_key, device_public_key_x, device_public_key_y)
        logger.info(f'Derived DHKey: {ECDHSecret.hex()}')

        # Generate Confirmation
        confirmation_inputs = (
            provisioning_invite[1:] + 
            provisioning_capabilities[1:] + 
            provisioning_start[1:] +
            public_key_x + 
            public_key_y + 
            device_public_key_x + 
            device_public_key_y
        )
        logger.info(f'Generated Confirmation Input: {confirmation_inputs.hex()}')
        confirmation_salt = s1(confirmation_inputs)
        logger.info(f'Generated Confirmation Salt: {confirmation_salt.hex()}')

        confirmation_key = k1(ECDHSecret, confirmation_salt, b"prck")
        logger.info(f'Generated Confirmation Key: {confirmation_key.hex()}')

        # Receive the Output OOB string from the device
        auth_value = input("Enter the authentication value displayed on the device: ")
        logger.info(f"User entered Authentication Value: {auth_value.encode().hex()}")
        auth_value = auth_value.encode().ljust(16, b'\x00')

        # Generate Provisioner Confirmation
        provisioner_random = get_random_bytes(16)  # Generate random value
        provisioner_confirmation = aes_cmac(confirmation_key, provisioner_random + auth_value)
        provisioner_confirmation_message = PROVISIONING_CONFIRMATION_OPCODE + provisioner_confirmation
        conn.send(provisioner_confirmation_message)
        logger.info(f'Sent Provisioner Confirmation Message: {provisioner_confirmation_message.hex()}')

        # Receive Device Confirmation
        device_confirmation_message = conn.recv(64)
        if device_confirmation_message[0:1] != PROVISIONING_CONFIRMATION_OPCODE:
            raise Exception("Invalid Provisioner Confirmation Message")
        device_confirmation = device_confirmation_message[1:]
        logger.info(f'Received Device Confirmation: {device_confirmation.hex()}')

        # Send Provisioner Random
        provisioner_random_message = PROVISIONING_RANDOM_OPCODE + provisioner_random 
        conn.send(provisioner_random_message)
        logger.info(f"Sent Provisioner Random Message: {provisioner_random_message.hex()}")

        # Receive Device Random
        device_random_message = conn.recv(64)
        if device_random_message[0:1] != PROVISIONING_RANDOM_OPCODE:
            raise Exception("Invalid Device Random")
        device_random = device_random_message[1:]
        logger.info(f'Received Device Random: {device_random.hex()}')

        # Checkout Confirmation
        expected_confirmation = aes_cmac(confirmation_key, device_random + auth_value)
        if expected_confirmation != device_confirmation:
            raise Exception("Failed to checkout Device Confirmation ")
        logger.info("Device Confirmation Verified")

        # Generate Device Salt, Session Key and Session Nonce
        provisioning_salt = s1(confirmation_salt + provisioner_random + device_random)
        session_key = k1(ECDHSecret, provisioning_salt, b'prsk')
        nonce = k1(ECDHSecret, provisioning_salt, b'prsn')
        session_nonce = nonce[-13:]

        # Generate and Send Provisioning Data 
        provisioning_data = (
            NetworkKey +
            KeyIndex +
            Flags +
            IVIndex +
            UnicastAddress
        )
        encrypted_provisioning_data, provisioning_data_mic = aes_ccm_encrypt(session_key, session_nonce, provisioning_data)
        provisioning_data_pdu = PROVISIONING_DATA_OPCODE + encrypted_provisioning_data + provisioning_data_mic
        conn.send(provisioning_data_pdu)
        logger.info(f'Sent Provisioning Data: {provisioning_data_pdu.hex()}')

        # TODO 5. Link close
        complete_message = conn.recv(16)
        if complete_message[0:1] != PROVISIONING_COMPLETE_OPCODE:
            raise Exception("Invalid Complete Message")
        logger.info('Received Complete Message')
        link_close_message = LINK_CLOSE_OPCODE + b'\x00'#TODO
        conn.send(link_close_message)
        logger.info(f'Sent Link Close Message:{link_close_message.hex()}')

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        conn.close()
        logger.info("Connection closed.")

def start_server(host='127.0.0.1', port=65432):
    server = listen(port, bindaddr=host)
    logger.info(f'Server listening on {host}:{port}')

    connection = server.wait_for_connection()
    logger.info(f'Connected by {connection.rhost}:{connection.rport}')

    start_outputOOB_provisioning(connection)

if __name__ == "__main__":
    start_server()
