<div align="center">

# Virtual and Distributed HSM
##### A cheaper, more practical, and secure way to protect your secret keys and perform cryptographic operations.

</div>

## ⇁ Context
Hardware Security Modules (HSMs) play a crucial role in enterprise environments by **safeguarding sensitive cryptographic keys** and **performing essential cryptographic operations**. However, these devices are _expensive and difficult to manage_, making them inaccessible to startups and small organizations. This work presents the development of a Virtual and Distributed HSM that can be practically deployed in real-world environments while providing robust security guarantees comparable to those of physical HSMs.

Our approach **leverages efficient protocols from the field of threshold cryptography**, specifically `distributed key generation`, `threshold signatures`, and `threshold symmetric encryption`, which are the key operations performed by HSMs. By distributing trust among multiple parties and ensuring that no single entity has full control over cryptographic keys, our solution enhances security and resilience against breaches for a fraction of the cost of real HSMs. These protocols are implemented in a **Byzantine Fault-Tolerant State Machine Replication system**, making it tolerable to asynchrony, faults, and intrusions. None of these techniques were implemented by previous works that addressed the same problem.

Additionally, our system can **support cryptocurrency wallets for securely managing cryptocurrencies**, such as Bitcoin and Ethereum. This demonstrates the flexibility and applicability of our solution, namely in the growing field of digital finance, where it provides a secure alternative to managing digital assets.

For more details about this work, under the directory [/docs](./docs) is available my Master's thesis dissertation resultant of this project, entitled _"Virtual and Distributed Hardware  Security Module for Secure Key Management"_. This work also culminated in the publishing of an article for the Portuguese conference INForum 2024.

## ⇁ Installation
* Install JDK 17;
* Make sure you have `unzip`, `cmake`, and `gcc` installed as well;
* Run the `build_relic.sh` script to install the RELIC library in the `/pairing` subdirectory, which our BLS signature implementation depends on, followed by the `build.sh` script to build the .so library;
* Next, in the project's root directory, run the command `./gradlew simpleLocalDeploy` to compile the project into a .jar file;

Now, everything is installed and ready to be tested!

## ⇁ Running the Project
To demonstrate how to run the project, we will use the setting of 4 servers, with 1 possible fault.

Inside the `/build/local` directory, use the `run.sh` to run the project as follows:
* `./run.sh hsm.server.HsmServerKt <server_id (0-3)>`
* `./run.sh hsm.client.HsmClientKt <operation> <client_id> ...`
* `./run.sh hsm.client.ThroughputLatencyEvaluationKt <operation> <client_id> ...`

Specifically, to test our project, you can use the `HsmClient` class or the `ThroughputLatencyEvaluation` class, which was used to perform the experimental evaluation presented in the [/docs](./docs). We have developed a ClientAPI, which can be used via CLI through the following commands:
```text
hsm.client.HsmClientKt                      keyGen           <client id> <index key id> <schnorr || bls || symmetric>
                                            sign             <client id> <index key id> <schnorr || bls> <data>
                                            enc              <client id> <index key id> <data>
                                            dec              <client id> <index key id> <ciphertext>
                                            getPk            <client id> <index key id> <schnorr || bls>
                                            valSign          <client id> <signature> <initial data>
                                            availableKeys    <client id>
                                            help
                                   
hsm.client.ThroughputLatencyEvaluationKt    keyGen    <initial client id> <number of clients> <number of reps> <index key id> <schnorr || bls || symmetric>
                                            sign      <initial client id> <number of clients> <number of reps> <index key id> <schnorr || bls> <data>
                                            valSign   <initial client id> <number of clients> <number of reps> <index key id> <schnorr || bls> <data>
                                            enc       <initial client id> <number of clients> <number of reps> <index key id> <data>
                                            dec       <initial client id> <number of clients> <number of reps> <index key id> <data>
                                            all       <initial client id> <number of clients> <number of reps>
```

### Example
The following commands demonstrate the usage of the operations of key generation, signature, and encryption/decryption.

First, initialize the required number of servers, in this case we are using 4:
```text
./run.sh hsm.server.HsmServerKt 0
./run.sh hsm.server.HsmServerKt 1
./run.sh hsm.server.HsmServerKt 2
./run.sh hsm.server.HsmServerKt 3
```

Then, execute the available operations using the client API:
```text
./run.sh hsm.client.HsmClientKt keyGen 1 myfirstblskeypair123 bls
./run.sh hsm.client.HsmClientKt keyGen 1 mysymmetrickeyid symmetric
./run.sh hsm.client.HsmClientKt sign 1 myfirstblskeypair123 bls SignThisUsefulMessagePlease
./run.sh hsm.client.HsmClientKt enc 1 mysymmetrickeyid VerySecretKey
./run.sh hsm.client.HsmClientKt dec 1 mysymmetrickeyid -5312fffa88a1fffffffefeffffffdfb248282d98fe761a0ed85f239dceb2ee5b7acb4b9c5ad61c292cfcd188d62f5affffffce00f866f24dd9eb10f2d48467e081c2c27d7753b4c4aa8b66c976f2eac99cb0dbba19f26fa32403df87da26fea8466cc6eb
```

##### NOTE: By default, the project is configured to work with 4 replicas, tolerating 1 fault; however, you can change these settings by changing the `host.config` file, adding more addresses, and the `system.config` file, changing the lines 66, 69, and 153 to your preferred values.
