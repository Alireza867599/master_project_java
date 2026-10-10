SFDAC — Java 21 Auction & Secure Multi-Party Computation

A six-role Java implementation of a secure auction and Multi-Party Computation (MPC) research prototype, adapted from the original C++ codebase.


Technology: Java 21, TCP sockets, cryptography, MPC, Merkle trees, Ethereum integration helpers, and zero-knowledge proof tooling.

Project status: Research prototype. The Java implementation passes its included unit, integration, and smoke tests, but full functional equivalence with the C++ implementation and production security have not been established.

Overview

SFDAC explores a privacy-preserving auction workflow in which buyers and sellers submit encrypted, signed information. Two auctioneer parties jointly process additive shares with assistance from a third MPC participant.

The prototype combines:

Additive secret sharing using arithmetic modulo 2^64

Encrypted and digitally signed bidder packets

Commitment generation and consistency checks

Merkle inclusion evidence

Multi-party sorting and auction clearing

Beaver triples for MPC computations

Encrypted delivery of proof-related payloads

Integration hooks for Ethereum smart contracts and zero-knowledge tooling

System architecture

flowchart TD
    B["Buyers and Sellers"] --> BB["BidderBoss"]
    B --> P0["P0 Auctioneer"]
    B --> P1["P1 Auctioneer"]
    BB --> P0
    BB --> P1
    P0 <--> P1
    P2["P2 MPC Helper"] --> P0
    P2 --> P1
    P0 --> PR["ProverParty"]
    P1 --> PR
    BB -.-> BC["Ethereum Integration"]

Main components

Component

Description

Bidder.java

Creates additive shares, encrypted packets, commitments, signatures and receipts

BidderBoss.java

Collects bidder submissions, manages Merkle evidence, relays packets and handles randomness reveal

P0.java

First auctioneer participating in input validation, sorting and clearing

P1.java

Second auctioneer holding complementary shares and participating in MPC

P2.java

Provides randomized MPC material, permutation data and Beaver triples

ProverParty.java

Receives encrypted proof payloads and processes them with external verification helpers

The auctioneers reuse AuctioneerParty.java, AuctioneerIngress.java, and AuctioneerMpc.java to keep their shared implementation consistent.

Repository structure

master_project_java/
├── src/
│   ├── Bidder.java
│   ├── BidderBoss.java
│   ├── P0.java
│   ├── P1.java
│   ├── P2.java
│   ├── ProverParty.java
│   ├── AuctioneerParty.java
│   ├── AuctioneerIngress.java
│   ├── AuctioneerMpc.java
│   ├── Secp256k1Ecies.java
│   ├── SimpleJson.java
│   └── Wire.java
├── tests/
│   ├── SelfTest.java
│   ├── IntegrationTest.java
│   ├── auctioneer_mpc_smoke.py
│   ├── six_party_smoke.py
│   ├── full_protocol_smoke.py
│   └── prover_reveal_smoke.py
├── .github/workflows/java-ci.yml
├── build.sh
├── test.sh
├── README.md
├── README_FA.md
└── PUBLISH_TO_GITHUB.md

Requirements

The Java build and automated tests require:

JDK 21 or newer

Bash-compatible terminal

Python 3

Python package cryptography

Node.js for JavaScript-backed mock tests

To integrate with the original live system, additional JavaScript helper scripts, cryptographic keys, Ethereum RPC access and deployed smart contracts are required. These external assets are not bundled.

Installation

Clone the repository:

git clone https://github.com/Alireza867599/master_project_java.git
cd master_project_java

Check your Java installation:

java -version
javac -version

Install the Python test dependency:

python3 -m pip install cryptography

Build the project:

chmod +x build.sh test.sh
./build.sh

The build creates classes/ and sfdac-java.jar.

Testing

Run the full test suite:

./test.sh

Or run Java tests individually:

java -cp classes SelfTest
java -cp classes IntegrationTest

Additional integration tests cover bidder packet processing, encrypted ProverParty transport, MPC sorting and clearing, and communication across all main roles.

The six-role smoke-test fixture checks a buyer bid of 90 and seller ask of 20, with the expected result:

K  = 1
Pb = 90
Ps = 20

These tests use mocked BabyJub/CCE and Ethereum helper behavior where required. Passing them does not prove the correctness of live blockchain or cryptographic integration.

Running the application

Each role has an executable Java entry point.

For example, start the MPC helper using:

java -cp sfdac-java.jar P2

P2 expects P0 and P1 to be ready to accept connections on ports 6001 and 6002.

Start the proof receiver with:

java -cp sfdac-java.jar ProverParty \
  --listen 7800 \
  --priv keys/ProverParty.elg.priv \
  --out-dir zk-snark/perm_payloads \
  --max-n 128

For full auction execution, configure and start P0 and P1, BidderBoss, and the bidder processes with consistent participant counts and session IDs. The original JavaScript helpers, keys, and blockchain configuration must be provided separately.

See README_FA.md for additional runtime instructions in Persian.

Default network ports

Service

Port

P0 buyer ingress

7000

P1 buyer ingress

7001

P0 seller ingress

7002

P1 seller ingress

7003

P0–P1 communication

6000

P2 → P0

6001

P2 → P1

6002

BidderBoss submissions

7500

BidderBoss randomness reveal

7700

ProverParty

7800

Messages use big-endian 64-bit binary framing, preserving the core C++ protocol conventions.

Security and implementation limitations

This implementation is intended for research, experimentation, and further development.

Important limitations include:

Some advanced C++ dispute-handling and adversarial-test features have not been fully reproduced in Java.

Real Ethereum smart-contract interactions and BabyJub/Sigma-CCE verification require external scripts and have not been validated end to end.

The custom secp256k1 implementation has not received an independent cryptographic security audit.

TCP communication does not provide TLS protection.

Automated tests use mock integrations where appropriate and cannot establish production security.

Never commit private keys, credentials, seed material, or sensitive runtime outputs to a public repository.

Continuous integration

The project includes a GitHub Actions workflow:

.github/workflows/java-ci.yml

The workflow configures Java 21 and Python, installs the required Python test dependency, and executes the build and smoke tests on pushes to the main branch and on pull requests.

Future development

Areas for further work include complete C++/Java behavioral parity, independent cryptographic verification, authenticated network transport, real smart-contract integration tests, malicious-input testing, and expanded zero-knowledge proof integration.

License

No license file is included in the current project snapshot. A license should be selected and added by the repository owner before representing the code as openly licensed.



Language: Java 21+

Project type: Experimental secure auction and MPC system
