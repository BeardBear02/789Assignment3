# Assignment3

## Task1

### Phase1

#### **Beacon Phase**

- **Provisioner**: It waits for a beacon message from the device. This message includes the device's UUID and OOB information. If the beacon type is invalid, the process is halted.

- **Device**: The device sends its beacon message to the provisioner, which includes the device’s UUID and other OOB information (`DeviceUUID`, `OOBInfo`,`URIdata`).

![image-20241203181600501](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203181600501.png)

#### **Link Open Phase**

- **Provisioner**: Sends a "link open" message to initiate the link with the device using the device’s UUID (`LINK_OPEN_OPCODE`).

![image-20241203181635275](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203181635275.png)

- **Device**: Receives the link open message and validates it. Upon success, it responds with a "link acknowledgment" message (`LINK_ACK_OPCODE`).

![image-20241203181652538](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203181652538.png)

#### **Provisioning Phase**

- **Provisioner**

  - Sends a provisioning invite to the device, which includes 

  ![image-20241203181747359](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203181747359.png)

  - Sends the provisioning start message with information about the encryption algorithm and other provisioning-related data.

  ![image-20241203181945590](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203181945590.png)

  - Generates its public key and sends it to the device.

- **Device**

  - Receives the provisioning and responds by sending its capabilities such as supported algorithms, OOB data sizes, and authentication actions.

  ![image-20241203181854035](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203181854035.png)

  - public key to the provisioner after generating it using elliptic curve cryptography.
  - Both devices exchange public keys and derive a shared secret (DHKey) based on the elliptic curve Diffie-Hellman protocol.



### Phase2

#### Exchange public Keys Phase

**Provisioner**:

- Generates its public key and sends it to the device.

![image-20241203182223966](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203182223966.png)

**Device**:

- Receives the provisioning invite, parses it, and responds by sending its public key to the provisioner after generating it using elliptic curve cryptography.
- Both devices exchange public keys and derive a shared secret (DHKey) based on the elliptic curve Diffie-Hellman protocol.

![image-20241203182241798](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203182241798.png)



### Phase3

#### **Authentication Phase**

The **Auth Value** is a random 8-byte string generated by the device using `generate_random_string(8)`.

This value is then **padded to 16 bytes** using `ljust(16, b'\x00')` to align it to the expected size for the authentication process.

![image-20241203182637588](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203182637588.png)

- **Provisioner**

  - Generates a confirmation key using the shared DH key and a confirmation salt derived from various messages exchanged.

    ![image-20241203182741356](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203182741356.png)

  - The provisioner generates a confirmation message and sends it to the device.

  ![image-20241203182801875](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203182801875.png)

- **Device**

  - Receives the confirmation message and generates its own confirmation based on the derived key and random data, sending it back to the provisioner for validation.
  - Verifies that the provisioner’s confirmation matches its own calculation.

  ![image-20241203182847089](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203182847089.png)



### Phase4

#### Data Encryption and Decryption

- **Provisioner**

  - Receives the device’s random data and the device’s confirmation message.
  - Encrypts provisioning data (such as network keys and other setup parameters) and sends it to the device.

  ![image-20241203183026982](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203183026982.png)

- **Device**

  - Decrypts the provisioning data and validates the integrity using the encryption parameters.

  ![image-20241203183111918](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203183111918.png)

  - Sends a completion message (`PROVISIONING_COMPLETE_OPCODE`), and the process is closed with a "link close" message.

  ![image-20241203183152537](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203183152537.png)



## Task2

### Weaknesses in the Provisioning Method and How to Exploit Them

The provisioning method described is vulnerable to a **Man-in-the-Middle (MITM) attack**, primarily due to the the exchange of critical messages. The attacker can exploit this to impersonate the `device`.

The simplest method I used to exploit this vulnerability was through a script called `attacker.py`. The idea is straightforward: after the device sends its **Provisioning Capabilities**, the attacker takes over and replaces the device in all subsequent interactions with the provisioner. 

#### Exploit Method

1. **Intercept Device Information:**

   - The MITM attacker positions themselves between the device and the provisioner.
   - The device sends unprotected messages, such as the **Beacon** and **Provisioning Capabilities**, which include details like the UUID .
   - The attacker intercepts and stores this information.

   ![image-20241203185047165](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203185047165.png)

2. **Abandon Device Interaction:**

   - After capturing the initial messages from the `device`, the attacker no longer needs to interact with `device`.
   - Instead, the attacker acts as a fake device, sending their own **public key** to the provisioner.

   ![image-20241203185110756](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203185110756.png)

3. **Exploit Confirmation Mechanism:**

   - The attacker does not compute its own **confirmation**. Instead, they reply the provisioner's **confirmation message** right back.

   ![image-20241203185225575](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203185225575.png)

   - Because the provisioner expects a response that matches its own confirmation (based on the shared secret), this reflection tricks the provisioner into believing the attacker is a legitimate participant in the provisioning process.

4. **Capture Provisioner Data:**

   - By successfully passing the confirmation step, the attacker gains access to **Provisioning Data PDU** sent by the provisioner.

![image-20241203185434135](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203185434135.png)

And decrypted:

![image-20241203224946973](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203224946973.png)



## Bonus

### Point1

Unlike the straightforward method described in `attacker.py`, where the attacker replaces the Device entirely in subsequent interactions with the Provisioner, the approach implemented in `attacker1.py` operates by maintaining communication with both the Provisioner and the Device as distinct entities. Instead of replacing the Device, the attacker acts as a **man-in-the-middle (MITM)**, creating two separate communication links with distinct public/private key pairs.

**Dual Key Pair Strategy**

- `attacker1.py` generates two unique public/private key pairs: one for communication with the Provisioner and another for the Device. This allows the attacker to establish two independent ECDH shared secrets.

![image-20241203211329948](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203211329948.png)

**AuthValue Derivation**

- In `attacker1.py`, the AuthValue is computed using intercepted messages and reverse-engineered cryptographic calculations. The attacker carefully preserves the integrity of the provisioning protocol by generating a valid Confirmation message for the Device.

This is the unique aspect of the attack is the calculation of the **AuthValue**

![image-20241203211546857](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203211546857.png)

![image-20241203211615109](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203211615109.png)



**AuthValue Calculation**
The attacker, having intercepted key messages like the Provisioning Confirmation and Provisioning Random, computes the AuthValue by reversing the cryptographic operations between the Provisioner and the Device. This involves decryption, subkey generation (via AES-CMAC), and XOR operations, as outlined in the cryptographic protocol.

![image-20241203232428857](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203232428857.png)

**Using AuthValue for Confirmation**
Once the AuthValue is calculated, it is used to create a valid Confirmation message for the Device. The Confirmation message is an essential part of the provisioning process, as it proves to the Device that the Provisioner and the Device are in sync with the correct cryptographic information.

**Seamless Interaction**:
By generating a valid Confirmation message for the Device, the attacker ensures that the Device believes it is still communicating with the legitimate Provisioner. As a result, the Device proceeds with its normal operations, unaware that the attacker has been intercepting and modifying the messages.



Additionally, the attacker uses the same **public key** and **ECDHSecret** (derived from the key exchange between the attacker and the Device) to encrypt the decrypted plaintext received from the Provisioner. This encrypted message is then sent to the Device, which successfully decrypts it as if it were part of the legitimate communication from the Provisioner. This process ensures that the entire interaction remains normal, with both the Device and Provisioner believing they are communicating securely.

This technique allows the attacker to maintain a transparent connection, making it difficult to detect the attack. Moreover, the attacker can continuously intercept, modify, and relay information between the two parties without raising suspicion, effectively maintaining control over the communication and access to sensitive data.

![image-20241203231841103](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203231841103.png)



### Point2

Compared to `attacker1.py`, `attacker2.py` introduces an improvement to make the attack less detectable. In `attacker1.py`, the strategy involved returning the Provisioner's Confirmation message in order to obtain the random value from the Provisioner. However, this approach could easily be detected by the Provisioner since it would notice that the Confirmation messages sent and received are the same, potentially exposing the attacker.

To overcome this vulnerability, `attacker2.py` adopts a more sophisticated method. Instead of directly relaying the Provisioner's Confirmation to the Device, the attacker first generates its own Confirmation message for the Device. This way, the attacker can independently compute the attacker's random value without the Provisioner noticing any anomaly in the communication. 

![image-20241203232326059](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203232326059.png)

![image-20241203232549234](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203232549234.png)

![image-20241203232815783](/Users/xiongzhuocheng/Library/Application Support/typora-user-images/image-20241203232815783.png)