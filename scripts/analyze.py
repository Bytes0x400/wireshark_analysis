# This is the file with the analysis functions

import ipaddress
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import re
import datetime
import pandas as pd
import warnings
import os
from prettytable import PrettyTable

# Initialize a PrettyTable to store the summary of the analysis
table_summary = PrettyTable()
table_summary.field_names = ['Description']
table_summary.align = 'l'
table_summary.title = 'Summary'
table_summary.max_width = 70

# Create a PrettyTable to store the warnings identified during the analysis
table_warnings = PrettyTable()
table_warnings.title = 'Warnings'
table_warnings.field_names = ['No.', 'Category', 'Description', 'Recommendation']
# Enable word wrapping for the 'Description' and 'Recommendation' columns
table_warnings.max_width["No."] = 5
table_warnings.max_width["Category"] = 15
table_warnings.max_width["Description"] = 25
table_warnings.max_width["Recommendation"] = 25
table_warnings.align = 'l'
count = 1

# Create a directory for the plots within the results directory
os.makedirs('../results/plots', exist_ok=True)
# Create a subdirectory within the plots folder with the current date and time
os.makedirs(f'../results/plots/{datetime.datetime.now().strftime("%m%d%y%H%M")}', exist_ok=True)

# Define the directory path for saving the plots
plots_dir = f'../results/plots/{datetime.datetime.now().strftime("%m%d%y%H%M")}'

###############################################Plotting Functions#############################################
# Function to plot a bar chart of the top 10 most frequent values in a specified column of a DataFrame
def Top10(dataframe, column, title, filename):
    """
    Plots a bar chart of the top 10 most frequent values in a specified column of a DataFrame.

    Parameters:
    dataframe (pd.DataFrame): The DataFrame containing the data.
    column (str): The column name to analyze.

    The function performs the following steps:
    1. Counts the occurrences of each unique value in the specified column.
    2. Selects the top 10 most frequent values.
    3. Plots a bar chart of these top 10 values.
    4. Sets the title, x-label, and y-label of the plot.
    5. If the maximum count exceeds 1000, sets the y-axis to a logarithmic scale.
    6. Annotates each bar with its corresponding count.
    7. Displays the plot.

    Note:
    - The function assumes that the `matplotlib.pyplot` module is imported as `plt`.
    - The function does not return any value; it only displays the plot.
    """
    
    dataframe[column].value_counts().head(10).plot(kind='bar')
    plt.title(f'Top 10 {title}')
    plt.xlabel(f'{column}')
    plt.ylabel('Number of Packets')
    if dataframe[column].value_counts().max() > 1000:
        plt.yscale('log')
    for i, v in enumerate(dataframe[column].value_counts().head(10)):
        plt.text(i, v + 10, str(v), ha='center')
    plt.savefig(os.path.join(plots_dir, filename))
    plt.show()

    
# Function to plot the analysis of a specific column in the data
def plot_analysis(title, data, column):
    """
    Plots a bar chart of the value counts for a specified column in a DataFrame.

    Parameters:
    title (str): The title of the plot.
    data (pd.DataFrame): The DataFrame containing the data.
    column (str): The column name to analyze.

    The function performs the following steps:
    1. Counts the occurrences of each unique value in the specified column.
    2. Groups values with counts less than 10 into an 'Others' category.
    3. Sorts the value counts in descending order.
    4. Plots a bar chart of the value counts.
    5. Sets the title and x-ticks of the plot.
    6. If the maximum count exceeds 1000, sets the y-axis to a logarithmic scale.
    7. Annotates each bar with its corresponding count.
    8. Colors the bars based on the count ranges and adds a legend.
    9. Aligns the plot to the center of the page.
    10. Saves the plot as a PNG file in the specified directory.
    11. Displays the plot.

    Note:
    - The function assumes that the `matplotlib.pyplot` module is imported as `plt`.
    - The function does not return any value; it only displays the plot.
    """
    
    # Count the occurrences of each unique value in the specified column
    protocol_value_counts = data[column].value_counts()
    
    # Group values with counts less than 10 into an 'Others' category
    others_count = protocol_value_counts[protocol_value_counts < 10].sum()
    protocol_value_counts = protocol_value_counts[protocol_value_counts >= 10]
    protocol_value_counts['Others'] = others_count
    
    # Sort the value counts in descending order
    protocol_value_counts = protocol_value_counts.sort_values(ascending=False)

    # Create a bar chart of the value counts
    plt.figure(figsize=(12, 6))
    plt.title(title)
    bars = plt.bar(protocol_value_counts.index, protocol_value_counts)
    
    # Set the y-axis to a logarithmic scale if the maximum count exceeds 1000
    if protocol_value_counts.max() > 1000:
        plt.yscale('log')
    
    # Rotate the x-ticks for better readability
    plt.xticks(rotation=90)
    
    # Annotate each bar with its corresponding count
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval, int(yval), va='bottom')  # va: vertical alignment
        
        # Color the bars based on the count ranges
        if yval >= 1000:
            bar.set_color('blue')
            blue_patch = mpatches.Patch(color='blue', label='1000+ packets')
        elif yval < 1000 and yval > 100:
            bar.set_color('orange')
            orange_patch = mpatches.Patch(color='orange', label='100-1000 packets')
        elif yval <= 100:
            bar.set_color('red')
            red_patch = mpatches.Patch(color='red', label='0-100 packets')
    
    # Add legend if there are different colors
    handles = []
    if 'blue_patch' in locals():
        handles.append(blue_patch)
    if 'orange_patch' in locals():
        handles.append(orange_patch)
    if 'red_patch' in locals():
        handles.append(red_patch)
    if handles:
        plt.legend(handles=handles)
    
    # Align the plot to the center of the page
    plt.gca().set_position([0.1, 0.1, 0.8, 0.8])
    
    # Save the plot as a PNG file in the specified directory
    plt.savefig(os.path.join(plots_dir, f'{title}.png'))
    
    # Display the plot
    plt.show()

###############################################IP Address Analysis#############################################

# function to identify the type of network address based on the given address and protocol  
def identify_address_type(address, protocol):
    """
    Identify the type of network address based on the given address and protocol.
    Parameters:
    address (str): The network address to be identified. It can be an IPv4, IPv6, or MAC address.
    protocol (str): The protocol associated with the address. It can be used to identify MAC addresses.
    Returns:
    str: The type of the address, which can be one of the following:
        - 'Private': If the address is a private IPv4 address (e.g., starts with '192.168.', '172.16.', or '10.').
        - 'IPv6': If the address is an IPv6 address.
        - 'MAC': If the protocol is 'ARP', indicating the address is a MAC address.
        - 'Public': If the address is a public IPv4 address.
    Example:
    >>> identify_address_type('192.168.1.1', 'TCP')
    'Private'
    >>> identify_address_type('2001:0db8:85a3:0000:0000:8a2e:0370:7334', 'TCP')
    'IPv6'
    >>> identify_address_type('00:1A:2B:3C:4D:5E', 'ARP')
    'MAC'
    >>> identify_address_type('8.8.8.8', 'TCP')
    'Public'
    """
    if protocol == 'ARP':
        return 'MAC'
    elif address.startswith('192.168.') or address.startswith('172.16.') or address.startswith('10.'):
        return 'Private'
    # Check if address is multicast ipv4 address
    elif ipaddress.ip_address(address).is_multicast:
        return 'Multicast-IPv4'
    elif ipaddress.ip_address(address).version == 6:
        return 'IPv6'
    else:
        return 'Public'
    
 

#########################################################################Data Analysis#########################################################################
warnings.filterwarnings("ignore")

def data_preprocessing(data):
    """
    Perform data preprocessing on the input DataFrame.

    This function performs the following steps:
    1. Checks for missing values in the dataset and removes rows with missing values.
    2. Identifies the type of network address for each source and destination address.

    Parameters:
    data (pd.DataFrame): The input DataFrame containing network data.

    Returns:
    pd.DataFrame: The preprocessed DataFrame with missing values removed and address types identified.
    """
    print("\nData Preprocessing")
    print("=" * 40)  # Separator for clarity
    table_summary.add_row(["*********Data Preprocessing*********"])

    # Check for missing values in the dataset
    if data.isnull().sum().sum() == 0:
        print("There are no missing values in the dataset")
        table_summary.add_row(["No missing values in the dataset"])
    else:
        print("There are missing values in the dataset")
        print(f"The total number of rows with missing values is {data.isnull().any(axis=1).sum()}")
        table_summary.add_row(["Missing values in the dataset"])
        table_summary.add_row([f"Total number of rows with missing values: {data.isnull().any(axis=1).sum()}"])
    
    # Remove rows with missing values
    data = data.dropna()
    print(f"The dataset has {data.shape[0]} rows and {data.shape[1]} columns after deleting rows with missing values")
    table_summary.add_row([f"Total number of rows after deleting rows with missing values: {data.shape[0]}"])

    # Identify the address type for each source and destination address
    data.loc[:, 'Source_Type'] = data.apply(lambda x: identify_address_type(x['Source'], x['Protocol']), axis=1)
    data.loc[:, 'Destination_Type'] = data.apply(lambda x: identify_address_type(x['Destination'], x['Protocol']), axis=1)
    
    # Add a blank row to the summary table for better readability
    table_summary.add_row([""])
    
    return data

def source_analysis(data):
    """
    Perform source analysis on the input DataFrame.

    This function performs the following steps:
    1. Analyzes the top 10 source addresses with the highest number of packets.
    2. Analyzes the top 10 private source addresses with the highest number of packets.
    3. Analyzes the top 10 public source addresses with the highest number of packets.
    4. Analyzes the top 10 IPv6 source addresses with the highest number of packets.
    5. Captures the top source IP address and the percentage of packets it sent.

    Parameters:
    data (pd.DataFrame): The input DataFrame containing network data.

    Returns:
    None
    """
    global count
    print("\nSource Analysis")
    print("=" * 40)  # Separator for clarity

    data_temp = data.copy()
    
    # Top 10 source addresses with the highest number of packets
    print("\nSource Analysis for All Addresses")
    if 'Source' in data_temp.columns:
        plot_filename = "top10_source_ips.png"
        Top10(data_temp, 'Source', 'Source IPs', plot_filename)
    else:
        print("The dataset does not have a 'Source' column")
        table_summary.add_row(["*********Source Analysis*********"])
        table_summary.add_row(["The dataset does not have a 'Source' column"])
        table_summary.add_row([""])
    
    # Drop all rows except for the Source Type is Private
    # First check if there exists Private Source addresses
    print("\nSource Analysis for Private Addresses")
    if len(data_temp[data_temp['Source_Type'] == 'Private']) > 0:
        plot_filename = "top10_private_source_ips.png"
        Top10(data_temp[data_temp['Source_Type'] == 'Private'], 'Source', 'Private Source IPs', plot_filename)
    else:
        print("The dataset does not have Private Source IPs")
        table_summary.add_row(["********Source Analysis for Private IPs********"])
        table_summary.add_row(["The dataset does not have Private Source IPs"])
        table_summary.add_row([""])

    # Top 10 Public source addresses with the highest number of packets
    print("\nSource Analysis for Public Addresses")
    if len(data_temp[data_temp['Source_Type'] == 'Public']) > 0:
        plot_filename = "top10_public_source_ips.png"
        Top10(data_temp[data_temp['Source_Type'] == 'Public'], 'Source', 'Public Source IPs', plot_filename)
    else:
        print("The dataset does not have Public Source IPs")
        table_summary.add_row(["********Source Analysis for Public IPs********"])
        table_summary.add_row(["The dataset does not have Public Source IPs"])
        table_summary.add_row([""])
    
    # Top 10 IPv6 source addresses with the highest number of packets
    print("Source Analysis for IPv6 Addresses")
    if len(data[data['Source_Type'] == 'IPv6']) > 0:
        plot_filename = "top10_ipv6_source_ips.png"
        Top10(data[data['Source_Type'] == 'IPv6'], 'Source', 'IPv6 Source IPs', plot_filename)
    else:
        print("The dataset does not have IPv6 Source IPs")
        table_summary.add_row(["********Source Analysis for IPv6 IPs********"])
        table_summary.add_row(["The dataset does not have IPv6 Source IPs"])
        table_summary.add_row([""])

    # Capture the top source IP address and the percentage of packets it sent
    top_source_ip = data['Source'].value_counts().idxmax()
    top_source_ip_packets = data['Source'].value_counts().max()

    table_summary.add_row(["***********Top Source IP Analysis***********"])
    if top_source_ip_packets > (data['Source'].count() / 2):
        table_summary.add_row([f"Top Source IP: {top_source_ip}"])
        table_summary.add_row([f"Total number of packets sent: {top_source_ip_packets}."])
        table_summary.add_row([f"Percentage of packets sent by the top Source IP: {round((top_source_ip_packets / data['Source'].count()) * 100, 2)}%."])
        table_warnings.add_row([f"{count}", 'Source IP', f'{top_source_ip} sent more than 50% of the total packets.', 'Investigate - potential malware or DDoS attack'])
        count += 1
    else:
        table_summary.add_row([f"Top Source IP: {top_source_ip}"])
        table_summary.add_row([f"Total number of packets sent: {top_source_ip_packets}."])
        table_summary.add_row([f"Percentage of packets sent by the top Source IP: {round((top_source_ip_packets / data['Source'].count()) * 100, 2)}%."])
        table_summary.add_row(["The top Source IP did not send more than 50% of the total packets."])

  

def destination_analysis(data):
    """
    Perform destination analysis on the input DataFrame.

    This function performs the following steps:
    1. Analyzes the top 10 destination addresses with the highest number of packets.
    2. Analyzes the top 10 private destination addresses with the highest number of packets.
    3. Analyzes the top 10 public destination addresses with the highest number of packets.
    4. Analyzes the top 10 IPv6 destination addresses with the highest number of packets.
    5. Captures the top destination IP address and the percentage of packets it received.

    Parameters:
    data (pd.DataFrame): The input DataFrame containing network data.

    Returns:
    None
    """
    global count
    print("\nDestination Analysis")
    print("=" * 40)  # Separator for clarity

    data_temp = data.copy()
    
    # Top 10 destination addresses with the highest number of packets
    print("\nDestination Analysis for All Addresses")
    if 'Destination' in data_temp.columns:
        plot_filename = "top10_destination_ips.png"
        Top10(data_temp, 'Destination', 'Destination IPs', plot_filename)
    else:
        print("The dataset does not have a 'Destination' column")
        table_summary.add_row(["*********Destination Analysis*********"])
        table_summary.add_row(["The dataset does not have a 'Destination' column"])
        table_summary.add_row([""])
    
    # Drop all rows except for the Destination Type is Private
    # First check if there exists Private Destination addresses
    print("\nDestination Analysis for Private Addresses")
    if len(data_temp[data_temp['Destination_Type'] == 'Private']) > 0:
        plot_filename = "top10_private_destination_ips.png"
        Top10(data_temp[data_temp['Destination_Type'] == 'Private'], 'Destination', 'Private Destination IPs', plot_filename)
    else:
        print("The dataset does not have Private Destination IPs")
        table_summary.add_row(["Destination Analysis for Private Addresses"])
        table_summary.add_row(["The dataset does not have Private Destination IPs"])
        table_summary.add_row([""])

    # Top 10 Public destination addresses with the highest number of packets
    print("\nDestination Analysis for Public Addresses")
    if len(data_temp[data_temp['Destination_Type'] == 'Public']) > 0:
        plot_filename = "top10_public_destination_ips.png"
        Top10(data_temp[data_temp['Destination_Type'] == 'Public'], 'Destination', 'Public Destination IPs', plot_filename)
    else:
        print("The dataset does not have Public Destination IPs")
        table_summary.add_row(["Destination Analysis for Public Addresses"])
        table_summary.add_row(["The dataset does not have Public Destination IPs"])
        table_summary.add_row([""])

    # Top 10 IPv6 destination addresses with the highest number of packets
    print("Destination Analysis for IPv6 Addresses")
    if len(data[data['Destination_Type'] == 'IPv6']) > 0:
        plot_filename = "top10_ipv6_destination_ips.png"
        Top10(data[data['Destination_Type'] == 'IPv6'], 'Destination', 'IPv6 Destination IPs', plot_filename)
    else:
        print("The dataset does not have IPv6 Destination IPs")
        table_summary.add_row(["Destination Analysis for IPv6 Addresses"])
        table_summary.add_row(["The dataset does not have IPv6 Destination IPs"])
        table_summary.add_row([""])

    # Capture the top destination IP address and the percentage of packets it received
    top_destination_ip = data['Destination'].value_counts().idxmax()
    top_destination_ip_packets = data['Destination'].value_counts().max()

    table_summary.add_row(["***********Top Destination IP Analysis***********"])
    if top_destination_ip_packets > (data['Destination'].count() / 2):
        table_summary.add_row([f"Top Destination IP: {top_destination_ip}"])
        table_summary.add_row([f"Total number of packets received: {top_destination_ip_packets}."])
        table_summary.add_row([f"Percentage of packets received by the top Destination IP: {round((top_destination_ip_packets / data['Destination'].count()) * 100, 2)}%."])
        table_warnings.add_row([f"{count}", 'Destination IP', f'{top_destination_ip} received more than 50% of the total packets.', 'Investigate - potential malware or DDoS attack'])
        count += 1
    else:
        table_summary.add_row([f"Top Destination IP: {top_destination_ip}"])
        table_summary.add_row([f"Total number of packets received: {top_destination_ip_packets}."])
        table_summary.add_row([f"Percentage of packets received by the top Destination IP: {round((top_destination_ip_packets / data['Destination'].count()) * 100, 2)}%."])
        table_summary.add_row(["The top Destination IP did not receive more than 50% of the total packets."])
 
######################################Protocol Analysis#############################################


def extract_TCP_details(data):
    """
    Extract TCP details from a given dataframe.

    Args:
        data (pd.DataFrame): The input dataframe containing TCP details in a specific format.

    Returns:
        pd.DataFrame: A dataframe with extracted TCP details including:
            - TCP_Msg (str): TCP message or 'None' if not present.
            - Source_Port (str): Source port.
            - Destination_Port (str): Destination port.
            - TCP_Control_Msg (str): The full TCP control message within brackets.
    """
    global count
    print("\nTCP Analysis")
    print("=" * 40)  # Separator for clarity
    table_summary.add_row(["*********TCP Analysis********"])
    # Create a tcp_data dataframe from the input data
    # Filter the dataframe for rows where Protocol is 'TCP'
    tcp_data = data[data['Protocol'] == 'TCP']

    if tcp_data.empty:
        print("No TCP data found in the input dataframe.")
        return pd.DataFrame()
    else:
        # Initialize lists to store extracted details
        tcp_msgs = []
        source_ports = []
        destination_ports = []
        tcp_control_msgs = []

        for info in tcp_data['Info']:
            # Initialize default values
            TCP_Msg = 'None'
            source_port = None
            destination_port = None
            tcp_control_msg = None

            # Split the input string based on ']'
            temp_string = info.split(']')
            
            try:
                # Determine if there's a TCP message at the start
                for element in temp_string:
                    if '>' in element:
                        item = temp_string.index(element)

                        if item == 0:
                            source_temp = temp_string[0].split('>')
                        elif item == 1:
                            TCP_Msg = temp_string[0].strip('[')
                            source_temp = temp_string[1].split('>')
                        elif item == 2:
                            TCP_Msg = temp_string[0].strip('[')
                            source_temp = temp_string[2].split('>')
                        else:
                            TCP_Msg = None
                            source_temp = None

                # Extract source port
                source_port = source_temp[0].strip()
                
                # Extract destination port and control message
                destination_temp = source_temp[1].split(' ')
                destination_temp = list(filter(None, destination_temp))  # Remove blank elements
                destination_port = destination_temp[0]
                
                # Capture the full control message within brackets
                control_msg_index = source_temp[1].find('[')
                if control_msg_index != -1:
                    tcp_control_msg = source_temp[1][control_msg_index:].strip('[]')  # Capture all within brackets

            except (IndexError, ValueError) as e:
                print(f"Error processing TCP details: {e} for input:{info}")

            # Append extracted details to lists
            tcp_msgs.append(TCP_Msg)
            source_ports.append(source_port)
            destination_ports.append(destination_port)
            tcp_control_msgs.append(tcp_control_msg)
        


        # Create a new dataframe with the extracted details
        extracted_data = pd.DataFrame({
            'Source': tcp_data['Source'].values,
            'Source_Port': source_ports,
            'Source_Type': tcp_data['Source_Type'].values,
            'Destination': tcp_data['Destination'].values,
            'Destination_Port': destination_ports,
            'Destination_Type': tcp_data['Destination_Type'].values,
            'TCP_Msg': tcp_msgs,
            'TCP_Control_Msg': tcp_control_msgs
        })
        # Create two new columns in the dataframe called 'SourceIP and Port' and 'DestinationIP and Port'.
        # Combine the Source and Destination IP addresses with their respective ports separated by a colon
        extracted_data['Source_IP:TCP_Port'] = extracted_data['Source'] + ':' + extracted_data['Source_Port']
        extracted_data['Destination_IP:TCP_Port'] = extracted_data['Destination'] + ':' + extracted_data['Destination_Port']
        # if TCP RST control messages are present, print the count of TCP RST control messages in the input data from total TCP control messages
        table_summary.add_row(["*********TCP Control Message Analysis*********"])
        if 'RST' in extracted_data['TCP_Control_Msg'].values:
            table_summary.add_row(["TCP RST Analysis"])
            table_summary.add_row([f"Total TCP RST control messages: {extracted_data['TCP_Control_Msg'].value_counts()['RST']} out of {extracted_data['TCP_Control_Msg'].count()} total TCP control messages"])
            # calculate the percentage of TCP RST control messages from the total TCP control messages rounded to 2 decimal places
            percent_rst = round((extracted_data['TCP_Control_Msg'].value_counts()['RST'] / extracted_data['TCP_Control_Msg'].count()) * 100, 2)
            table_summary.add_row([f"Percentage of TCP RST control messages: {percent_rst}%"])
            if percent_rst > 50:
                table_summary.add_row([f"Warning: Percentage of TCP RST control messages: {percent_rst}% (High) !!!  Might need investigation !!!"])
                table_warnings.add_row([f"'{count}','TCP RST','TCP RST control messages: {percent_rst}% (High)', 'Investigate further'"])
                count += 1
            elif percent_rst > 25:
                table_warnings.add_row([f"'{count}','TCP RST','TCP RST control messages: {percent_rst}% (Moderate)','Monitor'"])
                table_summary.add_row([f"Percentage of TCP RST control messages: {percent_rst}% (Moderate)\n"])
                count += 1
            else:
                table_summary.add_row([f"Percentage of TCP RST control messages: {percent_rst}% (Low)\n"])

        # Check the count of TCP SYN and SYN/ACK control messages in the input data
        if 'SYN' in extracted_data['TCP_Control_Msg'].values:
            table_summary.add_row(["TCP SYN Analysis"])
            percent_syn = round((extracted_data['TCP_Control_Msg'].value_counts()['SYN'] / extracted_data['TCP_Control_Msg'].count()) * 100, 2)
            table_summary.add_row([f"Total TCP SYN control messages: {extracted_data['TCP_Control_Msg'].value_counts()['SYN']} out of {extracted_data['TCP_Control_Msg'].count()} total TCP control messages"])
            if percent_syn > 50:
                table_summary.add_row([f"Percentage of TCP SYN control messages: {percent_syn}% (High) !!! Warning: Might need investigation !!!"])
                table_warnings.add_row([f"'{count}','TCP SYN','TCP SYN control messages: {percent_syn}% (High)','Investigate further'"])
                count += 1
            elif percent_syn > 25:
                table_summary.add_row([f"Percentage of TCP SYN control messages: {percent_syn}% (Moderate)"])
                table_warnings.add_row([f"'{count}','TCP SYN','TCP SYN control messages: {percent_syn}% (Moderate)','Monitor'"])
                count += 1
            else:
                table_summary.add_row([f"Percentage of TCP SYN control messages: {percent_syn}% (Low)"])
        
            if 'SYN, ACK' in extracted_data['TCP_Control_Msg'].values:
                percent_syn_ack = round((extracted_data['TCP_Control_Msg'].value_counts()['SYN, ACK'] / extracted_data['TCP_Control_Msg'].count()) * 100, 2)
                table_summary.add_row([f"Total TCP SYN/ACK control messages: {extracted_data['TCP_Control_Msg'].value_counts()['SYN, ACK']} out of {extracted_data['TCP_Control_Msg'].count()} total TCP control messages"])

            if percent_syn_ack > 50:
                table_summary.add_row([f"Percentage of TCP SYN/ACK control messages: {percent_syn_ack}% (High) !!! Warning: Might need investigation !!!"])
                table_warnings.add_row([f"{count}", 'TCP SYN/ACK', f"TCP SYN/ACK control messages: {percent_syn_ack}% (High)", "Investigate further"])
                count += 1
            elif percent_syn_ack > 25:
                table_summary.add_row([f"Percentage of TCP SYN/ACK control messages: {percent_syn_ack}% (Moderate)"])
                table_warnings.add_row([f"{count}", "TCP SYN/ACK", f"TCP SYN/ACK control messages: {percent_syn_ack}% (Moderate)", "Monitor"])
                count += 1
            else:
                table_summary.add_row([f"Percentage of TCP SYN/ACK control messages: {percent_syn_ack}% (Low)"])
         
            # if percent_syn and percent_syn_ack exist, compare the two values
            if percent_syn == percent_syn_ack:
                table_summary.add_row(["Percentage of TCP SYN and SYN/ACK control messages are equal, indicating a healthy environment."])
            elif percent_syn > percent_syn_ack:
                # if the difference between the percentage of SYN and SYN/ACK control messages is greater than 10, print a warning
                if percent_syn - percent_syn_ack > 10:
                    table_summary.add_row(["Warning: Percentage of TCP SYN control messages is higher than SYN/ACK control messages (Large difference)"])
                    table_warnings.add_row([f"{count}", "TCP SYN", "TCP SYN count > SYN/ACK count (Large difference)",'Investigate further']) 
                    count += 1
                else:
                    table_summary.add_row(["Percentage of TCP SYN control messages is higher than SYN/ACK control messages. This should be monitored for future captures."])
                    table_warnings.add_row([f"{count}", "TCP SYN", "TCP SYN count > SYN/ACK count", "Monitor"])
                    count += 1

            
                # if the difference between the percentage of SYN/ACK and SYN control messages is greater than 10, print a warning
            elif percent_syn_ack - percent_syn > 10:
                table_summary.add_row(["Warning: Percentage of TCP SYN/ACK control messages is higher than SYN control messages (Large difference)"])
                table_warnings.add_row([f"{count}", "TCP SYN/ACK", "TCP SYN/ACK count > SYN count (Large difference)", "Investigate further - potential SYN flood attack"])
                count += 1
            else:
                if percent_syn_ack != 0:
                    ratio = percent_syn / percent_syn_ack
                if ratio > 2:
                    table_summary.add_row(["Percentage of TCP SYN control messages is higher than SYN/ACK control messages. This should be monitored for future captures."])
                    table_warnings.add_row([f"{count}", "TCP SYN", "TCP SYN count > SYN/ACK count", "Monitor"])
                    count += 1
                else:
                    table_summary.add_row(["Percentage of TCP SYN/ACK control messages is higher than SYN control messages. This should be monitored for future captures."])
                    table_warnings.add_row([f"{count}", "TCP SYN/ACK", "TCP SYN/ACK count > SYN count", "Monitor"])
                    count += 1

        return extracted_data
    



###############################################ARP Analysis#################################################
# Function to extract ARP details from a given dataframe    
def extract_ARP_details(data):
    
    """
    Extract ARP details from a given dataframe.

    Args:
        data (pd.DataFrame): The input dataframe containing ARP details in a specific format.

    Returns:
        pd.DataFrame: A dataframe with extracted ARP details including:
            - ARP_Msg (str): ARP message or 'None' if not present.
            - Source_MAC (str): Source MAC address.
            - Destination_MAC (str): Destination MAC address.
            - ARP_Control_Msg (str): The full ARP control message within brackets.
    """
    print("\nARP Analysis")
    print("=" * 40)  # Separator for clarity
    # Create an arp_data dataframe from the input data
    # Filter the dataframe for rows where Protocol is 'ARP' and Info contains 'ARP'
    arp_data = data[(data['Protocol'] == 'ARP') & (data['Info'].str.contains('ARP')) | (data['Info'].str.contains('is at'))]
    if arp_data.empty:
        print("No ARP data found in the input dataframe.")
        return pd.DataFrame()
    else:
        arp_data.drop_duplicates(subset=['Info'], inplace=True)
        ip_mac_dict = {}

        # for each row in the arp_data dataframe extract the IP from the Info and MAC from the Source
        for index, row in arp_data.iterrows():
            # Extract the IP address from the Info column
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', row['Info'])
            # Extract the MAC address from the Source column
            if 'is at' in row['Info']:
                mac = row['Info'].split('is at ')[1].split(' ')[0]
            else:
                mac = row['Source']
            
            # Add the IP and MAC to the dictionary if they do not exist
            if ip and mac and ip[0] not in ip_mac_dict:
                ip_mac_dict[ip[0]] = mac

        # Print the dictionary using pprint
        print("IP and MAC Address Mapping")
        table_mac_mapping = PrettyTable()
        table_mac_mapping.field_names = ["IP Address", "MAC Address"]
        for ip, mac in ip_mac_dict.items():
            table_mac_mapping.add_row([ip, mac])
        print(table_mac_mapping)
        
        return ip_mac_dict
    
# Function to combine all the protocol analysis functions

def protocol_analysis(data):
    """
    Perform protocol analysis on the input DataFrame.

    This function performs the following steps:
    1. Plots the distribution of protocols in the data.
    2. Extracts TCP details from the data.
    3. Analyzes and plots the top 10 source and destination IP and TCP port combinations.
    4. Analyzes and plots the distribution of TCP messages and control messages.
    5. Extracts ARP details from the data.

    Parameters:
    data (pd.DataFrame): The input DataFrame containing network data.

    Returns:
    None
    """
    print("\nProtocol Analysis")
    print("=" * 40)  # Separator for clarity

    # Plot the distribution of protocols in the data
    plot_analysis('Protocol Distribution', data, 'Protocol')

    # Extract TCP details from the data
    extracted_data = extract_TCP_details(data)
    if extracted_data.empty:
        table_summary.add_row(["No TCP data found in the input dataframe."])
        return
    else:
        # Analyze and plot the top 10 source IP and TCP port combinations
        if 'Source_IP:TCP_Port' in extracted_data.columns:
            Top10(extracted_data, 'Source_IP:TCP_Port', 'Source IP and TCP Port combinations', 'top10_source_ip_tcp_port.png')
        
        # Analyze and plot the top 10 private source IP and TCP port combinations
        if 'Source_Type' in extracted_data.columns and 'Private' in extracted_data['Source_Type'].values:
            Top10(extracted_data[extracted_data['Source_Type'] == 'Private'], 'Source_IP:TCP_Port', 'Private Source IP and TCP Port combinations', 'top10_private_source_ip_tcp_port.png')
        
        # Analyze and plot the top 10 public source IP and TCP port combinations
        if 'Source_Type' in extracted_data.columns and 'Public' in extracted_data['Source_Type'].values:
            Top10(extracted_data[extracted_data['Source_Type'] == 'Public'], 'Source_IP:TCP_Port', 'Public Source IP and TCP Port combinations', 'top10_public_source_ip_tcp_port.png')
        
        # Analyze and plot the top 10 destination IP and TCP port combinations
        if 'Destination_IP:TCP_Port' in extracted_data.columns:
            Top10(extracted_data, 'Destination_IP:TCP_Port', 'Destination IP and TCP Port combinations', 'top10_destination_ip_tcp_port.png')
        
        # Analyze and plot the top 10 private destination IP and TCP port combinations
        if 'Destination_Type' in extracted_data.columns and 'Private' in extracted_data['Destination_Type'].values:
            Top10(extracted_data[extracted_data['Destination_Type'] == 'Private'], 'Destination_IP:TCP_Port', 'Private Destination IP and TCP Port combinations', 'top10_private_destination_ip_tcp_port.png')
        
        # Analyze and plot the top 10 public destination IP and TCP port combinations
        if 'Destination_Type' in extracted_data.columns and 'Public' in extracted_data['Destination_Type'].values:
            Top10(extracted_data[extracted_data['Destination_Type'] == 'Public'], 'Destination_IP:TCP_Port', 'Public Destination IP and TCP Port combinations', 'top10_public_destination_ip_tcp_port.png')
        
        # Analyze and plot the distribution of TCP messages
        if 'TCP_Msg' in extracted_data.columns:
            plot_analysis('TCP Messages Distribution', extracted_data, 'TCP_Msg')
        
        # Analyze and plot the distribution of TCP control messages
        if 'TCP_Control_Msg' in extracted_data.columns:
            plot_analysis('TCP Control Messages Distribution', extracted_data, 'TCP_Control_Msg')
        
        # Extract ARP details from the data
        extract_ARP_details(data)

###############################################Data Analysis#############################################

# Function to perform data analysis
def data_analysis(data):
    """
    Perform comprehensive data analysis on the input DataFrame.

    This function performs the following steps:
    1. Preprocesses the data to handle missing values and identify address types.
    2. Analyzes the source addresses in the data.
    3. Analyzes the destination addresses in the data.
    4. Analyzes the protocols in the data, including TCP and ARP details.

    Parameters:
    data (pd.DataFrame): The input DataFrame containing network data.

    Returns:
    None
    """
    # Step 1: Preprocess the data
    data = data_preprocessing(data)
    
    # Step 2: Analyze the source addresses
    source_analysis(data)
    
    # Step 3: Analyze the destination addresses
    destination_analysis(data)
    
    # Step 4: Analyze the protocols in the data
    protocol_analysis(data)
    
    # Print the summary table at the end
    print(table_summary)
    
    # Print the warnings table at the end
    print(table_warnings)
    
    # Notify the user where the graphs/plots have been saved
    print(f"\nThe graphs/plots have been saved in the {plots_dir}")

    
    
