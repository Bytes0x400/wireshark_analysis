# # Wireshark Analysis

Analyze network traffic using Wireshark capture.

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Explanation](#explanation)

## Introduction
Wireshark Analysis is a tool designed to analyze network traffic data captured by Wireshark. It provides insights into network behavior, helps identify anomalies, and supports various network analysis tasks.

## Features
- **Data Parsing**: Parse and process network traffic data from Wireshark capture files.
- **Traffic Analysis**: Analyze different types of network traffic, including TCP, UDP, and DNS.
- **Visualization**: Generate visualizations to help understand network traffic patterns.


## Installation
To install the necessary dependencies, run the following command:
pip install -r requirements.txt

### Explanation of the dependencies
pandas: For data manipulation and analysis.
requests: For making HTTP requests.
python-dotenv: For loading environment variables from a .env file.
matplotlib: For creating visualizations.

## DNS Resolution
<!-- This section of the README.md file describes the DNS resolution process -->
<!-- which was performed using the DRIFTNET API. -->
DNS resolution was done using the DRIFTNET API.
For more information, visit [DRIFTNET](https://driftnet.io).

The public IPs found in the capture are used alongwith the DRIFTNET API to get the FQDNs and use them in the analysis. 


### Explanation
- **Introduction**: 
This project is an outcome of trying to understand my home network traffic. The data for this project was a wireshark capture in promiscuous mode. The capture file was converted to a csv for the analysis. 


- **Features**: The outputs from the project are:
1. Source & Destination Analysis
    a. Source IP addresses
    b. Destination IP addresses
    c. External Domains accessed
2. Protocol Distribution
    a. Summary of the various protocols identified
3. TCP Analysis
    a. Summary of the TCP Messages
    b. Summary of the TCP Control Messages
4. ARP Analysis
    a. IP and MAC-Address mapping

- **Usage**: Basic usage instructions, including an example.


- **Contributing**: Information on how to contribute to the project.
- **License**: Licensing information.

