#!/usr/bin/env python3
import logging
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from toolbox import *

DeviceUUID = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
OOBInfo = b'\x04\x00' # Type of Number
URIdata = b'This is URI data'

# Provisioning Capabilities
number_of_elements = b'\x01'
algorithms = b'\x00\x00'
public_key_type = b'\x00'
static_oob_type = b'\x00'
output_oob_size = b'\x08' # Output OOB is available (8 bytes long)
output_oob_action = b'\x00\x10' # Show a string
input_oob_size = b'\x00'
input_oob_action = b'\x00\x00'

# Create and configure logger
logger = logging.getLogger('device')
logger.setLevel(logging.DEBUG)  # Logger level

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(console_handler)

def start_outputOOB_provisioning(host, port):
    conn = remote(host, port)
    logger.info(f'Connected to server at {host}:{port}')

    try:
        #TODO 1. Send Beacon
        beacon = BEACON_TYPE + DeviceUUID + OOBInfo + URIdata
        conn.send(beacon)
        logger.info(f'Sent Beacon: {beacon.hex()}')

        #TODO 2. Receive Link Open Message
        link_open_message = conn.recv(64)
        logger.info(f'Received Link Open Message: {link_open_message.hex()}')
        if link_open_message[0:1] != LINK_OPEN_OPCODE:
            raise Exception("Invalid Link Open Message")
        if link_open_message[1:17] != DeviceUUID:
            raise Exception("Wrong DeviceUUID")

        #TODO 3. Send Link Ack Message
        link_ack_message = LINK_ACK_OPCODE
        conn.send(link_ack_message)
        logger.info(f'Sent Link Ack Message: {link_ack_message.hex()}')

        #TODO 4. Provisioning starts
        # Implement the provisioning process here
        # Recieve Provisioning Invite
        provisioning_invite = conn.recv(64)
        if provisioning_invite[0:1] != PROVISIONING_INVITE_OPCODE:
            raise Exception("Invalid Provisioning Invite Message")
        logger.info(f'Received Provisioning Invite: {provisioning_invite.hex()}')

        # Send Provisioning Capabilities
        provisioning_capabilities = (
            PROVISIONING_CAPABILITIES_OPCODE +
            number_of_elements +
            algorithms +
            public_key_type +
            static_oob_type +
            output_oob_size +
            output_oob_action +
            input_oob_size +
            input_oob_action
        )
        conn.send(provisioning_capabilities)
        logger.info(f'Sent Provisioning Capabilities: {provisioning_capabilities.hex()}')

        # Receive Provisioning Start
        provisioning_start = conn.recv(1024)
        if provisioning_start[0:1] != PROVISIONING_START_OPCODE:
            raise Exception("Invalid Provisioning Start Message")
        logger.info(f'Received Provisioning Start Message: {provisioning_start.hex()}')

        # Recieve key from provisoner
        prov_public_key_message = conn.recv(1024)
        if prov_public_key_message[0:1] != PROVISIONING_PUBLIC_KEY_OPCODE:
            logger.error("Invalid opcode received! Expected provisioning public key message.")
            raise ValueError("Received message with invalid opcode.")
        prov_public_key_x = prov_public_key_message[1:33]
        prov_public_key_y = prov_public_key_message[33:65]
        logger.info(f'Received Provisioner Public Key: {prov_public_key_message.hex()}')

        
        # Generate Key Pair and Send to Provisioner
        private_key, public_key_x, public_key_y = generate_key_pair()
        public_key_message = PROVISIONING_PUBLIC_KEY_OPCODE + public_key_x + public_key_y
        conn.send(public_key_message)
        logger.info(f'Sent Public Key: {public_key_message.hex()}')

        # Derive DHKey
        ECDHSecret = derive_dhkey(private_key, prov_public_key_x, prov_public_key_y)
        logger.info(f'Derived DHKey: {ECDHSecret.hex()}')

        # Generate Confirmation
        confirmation_inputs = (
            provisioning_invite[1:] +
            provisioning_capabilities[1:] + 
            provisioning_start[1:] +
            prov_public_key_x + 
            prov_public_key_y + 
            public_key_x + 
            public_key_y
        )
        logger.info(f'Generated Confirmation Input: {confirmation_inputs.hex()}')
        confirmation_salt = s1(confirmation_inputs)
        logger.info(f'Generated Confirmation Salt: {confirmation_salt.hex()}')

        confirmation_key = k1(ECDHSecret, confirmation_salt, b"prck")
        logger.info(f'Generated Confirmation Key: {confirmation_key.hex()}')

        # Generate Auth Value
        auth_value = generate_random_string(8)
        logger.info(f"Generated Authentication Value (Device): {auth_value}")
        auth_value = auth_value.encode().ljust(16, b'\x00')

        # Receive Provisioner Confirmation
        provisioner_confirmation_message = conn.recv(64)
        if provisioner_confirmation_message[0:1] != PROVISIONING_CONFIRMATION_OPCODE:
            raise Exception("Invalid Provisioner Confirmation Message")
        provisioner_confirmation = provisioner_confirmation_message[1:]
        logger.info(f'Received Provisioner Confirmation: {provisioner_confirmation.hex()}')

        # Send Device Confirmation
        device_random = get_random_bytes(16)
        device_confirmation = aes_cmac(confirmation_key, device_random + auth_value)
        device_confirmation_message = PROVISIONING_CONFIRMATION_OPCODE + device_confirmation
        conn.send(device_confirmation_message)
        logger.info(f'Sent Device Confirmation Message: {device_confirmation_message.hex()}')

        # Receive Provisioner Random
        provisioner_random_message = conn.recv(64)
        logger.info(f'Received Provisioner Random: {provisioner_random_message.hex()}')
        if provisioner_random_message[0:1] != PROVISIONING_RANDOM_OPCODE:
            raise Exception("Invalid Provisioner Random")
        provisioner_random = provisioner_random_message[1:]

        # Send Device Random
        device_random_message = PROVISIONING_RANDOM_OPCODE + device_random 
        conn.send(device_random_message)
        logger.info(f"Sent Device Random Message: {device_random_message.hex()}")

        # Checkout Confirmation
        expected_confirmation = aes_cmac(confirmation_key, provisioner_random + auth_value)
        if expected_confirmation != provisioner_confirmation:
            raise Exception("Failed to checkout Provisioner Confirmation ")
        logger.info("Provisioner Confirmation Verified")

        # Generate Provisioning Salt, Session Key and Session Nonce
        provisioning_salt = s1(confirmation_salt + provisioner_random + device_random)
        session_key = k1(ECDHSecret, provisioning_salt, b'prsk')
        nonce = k1(ECDHSecret, provisioning_salt, b'prsn')
        session_nonce = nonce[-13:]
        cipher = AES.new(session_key, AES.MODE_CCM, nonce=session_nonce, mac_len=8)

        # Recieve Provisioning data
        provisioning_data_pdu = conn.recv(1024)
        if provisioning_data_pdu[0:1] != PROVISIONING_DATA_OPCODE:
            raise Exception("Invalid Provisioning Data")
        logger.info(f'Received Provisioner Data: {provisioning_data_pdu.hex()}')
        encrypted_provisioning_data = provisioning_data_pdu[1:-8]
        provisioning_data_mic = provisioning_data_pdu[-8:]

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

        #TODO 5. Send Provisioning Complete
        complete_message = PROVISIONING_COMPLETE_OPCODE
        conn.send(complete_message)
        logger.info('Sent Complete Message')

        #TODO 6. Receive Link Close Message
        link_close_message = conn.recv(16)#TODO
        if link_close_message[0:1] != LINK_CLOSE_OPCODE:
            raise Exception("Invalid Link Close Message")
        logger.info(f'Received Link Close Message:{link_close_message.hex()}')

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        conn.close()
        logger.info("Connection closed.")

if __name__ == "__main__":
    start_outputOOB_provisioning('127.0.0.1', 65433)
