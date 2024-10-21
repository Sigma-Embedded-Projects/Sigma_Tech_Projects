# Welcome to the Sigma Tech Projects Repository!

Hey Sigma Embedded fans! 🎉 We're thrilled to have you here. This repository is the heart of all our exciting tech endeavors. Whether you're here to contribute, learn, or just explore, you've come to the right place.

## About Sigma Tech Projects
The Sigma Tech Projects repository is dedicated to driving innovation and sharing knowledge in the tech community. From cutting-edge projects to insightful discussions, we're all about pushing the boundaries of technology.

## Repository Overview

### What You'll Find Here
- **Project Code:** Access the source code for our latest tech projects.
- **Documentation:** Comprehensive guides and references to help you understand and contribute to our projects.
- **Issues and Discussions:** Engage with the community, report issues, and discuss solutions.

### How to Contribute
We welcome contributions from everyone! Whether it's improving our documentation, adding new features, or reporting bugs, your input is invaluable. Here's how you can get started:
1. **Fork the repository:** Create your own copy of the repository.
2. **Clone the repository:** Download your fork to your local machine.
3. **Submit a pull request:** Send your changes for review.

## Stay Connected
Don't miss out on any updates! Follow us on our social media channels:
- **[LinkedIn/Page](https://www.linkedin.com/company/sigma-embedded)**
- **[LinkedIn/Groupe](https://www.linkedin.com/groups/12842283/)**
- **[Youtube](https://www.youtube.com/@SigmaEmbedded-md4dm)**

## List of Projects
### Project 1 : UART_Xmodem_Bootloader

This project is a bootloader for the STM32L5 microcontroller series (You can customize it for your specific STM32). It allows uploading a .bin file to the microcontroller via UART using the Xmodem protocol.

#### Features
- UART Communication: Utilizes UART for serial communication between the host PC and the STM32L5.
- Xmodem Protocol: Implements the Xmodem protocol for reliable file transfer.

#### Getting Started
- Hardware Setup: Connect the STM32L5 to a PC using a UART interface (STlink).
- Software Setup: Clone this repository and open it in your preferred IDE (STM32CubeIDE).
- Upload Process: Use the provided scripts or tools (Tera Term) to upload the .bin file via UART.

#### Usage
1. Prepare the .bin File: Ensure your firmware is compiled into a .bin file.
2. Run the Bootloader: Start the bootloader on the STM32L5.
3. Upload the File: Use the Xmodem protocol to upload the .bin file from your PC to the STM32L5.


Happy coding! 🚀
