# nchat

This project is an encrypted peer-to-peer network chat and relay application designed for terminal use. It leverages the libsodium library for robust cryptography.

## Features

* Peer-to-Peer Communication: Direct communication between peers without the need for a central server.

* Encryption: All messages are encrypted end-to-end using libsodium, ensuring secure communication. A set of ephemeral asymmetric keys are generated on both ends when a connection is made.

* Relay Functionality: Relay messages between peers to facilitate communication in a network.

## Installation

```
# On Debian-based systems
sudo apt-get install libsodium-dev

# On Red Hat-based systems
sudo yum install libsodium-devel

# On macOS
brew install libsodium
```

```
git clone https://github.com/thejostler/nchat
cd nchat
make
sudo make install
```

## Contributing
Contributions are welcome! Please fork this repository and submit a pull request with your changes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contact
For any questions or suggestions, please open an issue or reach out to me at [josj@tegosec.com](josj@tegosec.com)