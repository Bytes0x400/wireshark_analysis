# # Wireshark Analysis

Quick analysis of a  wireshark capture.

## Table of Contents
- [Introduction](#introduction)
- [Explanation](#explanation)
- [Project Structure](#project-structure)
- [Description](#description)
- [Explanation of the dependencies](#explanation-of-the-dependencies)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## Introduction
- **Origin**
This project originated from an effort to understand the traffic on my home network. The data used for this analysis was obtained from a wireshark capture in promiscuous mode. The capture file was then converted to a CSV format for further analysis. 
- **Purpose**
Wireshark Analysis is a tool to generate a quick report from a wireshark capture. The purpose is to provide a report with plots, graphs and analysis that can be used to create a baseline over time and understand the behavior of the environment or to help focus troubleshooting in the right direction. 

## Explanation

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
5. Summary
6. Warnings

## Project Structure
```
/wireshark_analysis
|-- /data
|   |-- capture.pcap
|   |-- capture.csv
|-- /scripts
|   |-- analyze.py
|   |-- analyze_dns.py
|   |-- notebook_run.py
|-- /notebooks
|   |-- analysis.ipynb
|-- /results
|   |-- analysis_results_YYYYMMDDHHMM.pdf
|   |-- /plots
|       |-- /YYYYMMDDHHMM
|           |-- top10_private_source_ips.png
|-- requirements.txt
|-- README.md
```
## Description

- **/data**: Contains the data files used for analysis.
  - `capture.pcap`: A packet capture file.
  - `capture.csv`: The packet capture converted to CSV, file used for the analysis.

- **/scripts**: Contains the Python scripts used for analysis.
  - `analyze.py`: The main analysis script, contains all the functions used in the project.
  - `analyze_dns.py`: A script for DNS analysis.
  - `notebook_run.py`: A script to run the Jupyter notebook and convert it to PDF.

- **/notebooks**: Contains Jupyter notebooks used for analysis.
  - `analysis.ipynb`: The main analysis notebook.

- **/results**: Contains the output files generated by the analysis.
  - `analysis_results_YYYYMMDDHHMM.pdf`: The PDF report generated from the analysis notebook, where YYYYMMDDHHMM is the date and time the report is generated.
  - **/plots/YYYYMMDDHHMM**: Contains plot images generated during the analysis, new folder created for every analysis where YYYYMMDDHHMM is the date and time of the analysis.
   
- **requirements.txt**: Lists the dependencies required for the project.

- **README.md**: Provides an overview and instructions for the project.

## Explanation of the dependencies
- `pandas`: A powerful data manipulation and analysis library for Python.
- `requests`: A simple HTTP library for making requests to web services.
- `matplotlib`: A plotting library for creating static, animated, and interactive visualizations in Python.
- `nbformat`: A library to read and write Jupyter notebook files.
- `nbconvert`: A tool to convert Jupyter notebooks to various formats, such as HTML and PDF.
- `sys`: A module that provides access to some variables used or maintained by the Python interpreter.
- `os`: A module that provides a way of using operating system dependent functionality.
- `datetime`: A module that supplies classes for manipulating dates and times.
- `ipaddress`: A module for creating, manipulating, and operating on IPv4 and IPv6 addresses and networks.
- `warnings`: A module to issue warning messages and control their behavior.
- `PrettyTable`: A library to create ASCII tables in Python.

## Installation
To install the necessary dependencies, run the following command:
pip install -r requirements.txt

## Usage 
(After the dependencies are installed): 
1. Use a wireshark capture file with extension of .pcap.
2. This should be the default and basic capture file, that contains the following columns: Time, Source, Destination, Protocol, Length and Info
3. Convert the capture to a csv with utf-8 encoding
4. Create a folder structure as below and copy the files in the respective folders:
/wireshark_analysis
|-- /data
|   |-- capture.pcap
|   |-- capture.csv
|-- /scripts
|   |-- analyze.py
|   |-- analyze_dns.py
|   |-- notebook_run.py
|-- /notebooks
|   |-- analysis.ipynb
The 'results' and the 'results/plots' folders will be created first time you run the program.
5. Open the notebook_run.py using your favorite editor and make sure the 'notebook_path' and 'output_path' variables are pointing to the right folder structures. 
6. (Optional) If the folder structure is different, then open the analyze.py file and search for the plots_dir and update it to point to right location.
7. Open the analysis.ipynb notebook and confirm the capture file csv location is accurate.
8. Go to the terminal and from within the scripts directory run "python notebook_run.py"

![Wireshark Analysis Video](https://github.com/Bytes0x400/wireshark_analysis/blob/main/capture.gif)

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request. For major changes, please open an issue first to discuss what you would like to change. Make sure to update tests as appropriate.

## License
 This project is licensed under the MIT License. See the [LICENSE](https://opensource.org/licenses/MIT) file for more details.

## Disclaimer
This project is intended for educational and informational purposes only. The analysis and results generated by this tool are based on the data captured by the author and the respective methods. The accuracy and reliability of the results depend on the quality and completeness of the input data. Use this tool responsibly and ensure compliance with all applicable laws and regulations when capturing and analyzing network traffic. The author/s is/are not responsible for any misuse or damage caused by the use of this tool.

