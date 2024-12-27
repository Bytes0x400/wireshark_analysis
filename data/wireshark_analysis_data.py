# This is the file with the analysis functions

import ipaddress
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import re
from IPython.display import display, HTML
import pandas as pd
import warnings
from data.wireshark_analysis_data_dns import dns_analysis
import os

###############################################Plotting Functions#############################################
# Function to plot a bar chart of the top 10 most frequent values in a specified column of a DataFrame

def Top10(dataframe, column, title):
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
    plt.show()

    
# Function to plot the analysis of a specific column in the data
def plot_analysis(title,data, column):
    
    protocol_value_counts = data[column].value_counts()
    # put value counts less than 10 in the 'Others' category
    others_count = protocol_value_counts[protocol_value_counts < 10].sum()
    protocol_value_counts = protocol_value_counts[protocol_value_counts >= 10]
    protocol_value_counts['Others'] = others_count
    protocol_value_counts = protocol_value_counts.sort_values(ascending=False)

    plt.figure(figsize=(12, 6))
    plt.title(title)
    bars = plt.bar(protocol_value_counts.index, protocol_value_counts)
    if protocol_value_counts.max() > 1000:
        plt.yscale('log')
    plt.xticks(rotation=90)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval, int(yval), va='bottom')  # va: vertical alignment
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
    # align the plot to the center of the page
    plt.gca().set_position([0.1, 0.1, 0.8, 0.8]) 
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
    display(HTML("<h1 style='text-align:center; font-weight:bold;'>Data Preprocessing</h1>"))
    if data.isnull().sum().sum() == 0:
        display(HTML("<ul><li>There are no missing values in the dataset</li></ul>"))
    else:
        display(HTML("<ul><li>There are missing values in the dataset</li></ul>"))
        display(HTML("<ul><li>The total number of rows with missing values is {}</li></ul>".format(data.isnull().any(axis=1).sum())))
    data = data.dropna()
    display(HTML("<ul><li>The dataset has {} rows and {} columns after deleting rows with missing values</li></ul>".format(data.shape[0], data.shape[1])))

    # Identify the address type for each source and destination address using the identify_address_type function
    data.loc[:, 'Source_Type'] = data.apply(lambda x: identify_address_type(x['Source'], x['Protocol']), axis=1)
    data.loc[:, 'Destination_Type'] = data.apply(lambda x: identify_address_type(x['Destination'], x['Protocol']), axis=1)

    return data

    

def source_analysis(data):
    display(HTML("<h1 style='text-align:center; font-weight:bold;'>Source Analysis</h1>"))
    
    data_temp = data.copy()
    # Top10 source addresses with the highest number of packets
    display(HTML("<h2 style='text-align:center; font-weight:bold;'>Source Analysis for All Addresses</h2>"))
    Top10(data_temp, 'Source', 'Source IPs')
    
    # drop all rows except for the Source Type is Private
    display(HTML("<h2 style='text-align:center; font-weight:bold;'>Source Analysis for Private Addresses</h2>"))
    # plot the bar chart for the top 10 private source addresses
    Top10(data_temp[data_temp['Source_Type'] == 'Private'], 'Source', 'Private Source IPs')

    # Top 10 Public source addresses with the highest number of packets
    display(HTML("<h2 style='text-align:center; font-weight:bold;'>Source Analysis for Public Addresses</h2>"))
    Top10(data_temp[data_temp['Source_Type'] == 'Public'], 'Source', 'Public Source IPs')

    # Top 10 IPv6 source addresses with the highest number of packets
    display(HTML("<h2 style='text-align:center; font-weight:bold;'>Source Analysis for IPv6 Addresses</h2>"))
    Top10(data_temp[data_temp['Source_Type'] == 'IPv6'], 'Source', 'IPv6 Source IPs')

  

# Function to analyze the destination column
def destination_analysis(data):
    display(HTML("<h1 style='text-align:center; font-weight:bold;'>Destination Analysis</h1>"))
    
    data_temp = data.copy()
    # Top 10 destination addresses with the highest number of packets
    display(HTML("<h2 style='text-align:center; font-weight:bold;'>Destination Analysis for All Addresses</h2>"))
    Top10(data_temp, 'Destination', 'Destination IPs')
   
    # Top10 Public destination addresses with the highest number of packets
    display(HTML("<h2 style='text-align:center; font-weight:bold;'>Destination Analysis for Public Addresses</h2>"))
    Top10(data_temp[data_temp['Destination_Type'] == 'Public'], 'Destination', 'Public Destination IPs')
    
 
######################################Protocol Analysis#############################################


###############################################TCP Analysis#################################################
# Function to extract TCP details from a given dataframe
def extract_TCP_details(data):
    display(HTML("<h1 style='text-align:center; font-weight:bold;'>TCP Analysis</h1>"))
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
    # Create a tcp_data dataframe from the input data
    # Filter the dataframe for rows where Protocol is 'TCP'
    tcp_data = data[data['Protocol'] == 'TCP']

    
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
    return extracted_data

###############################################ARP Analysis#################################################
# Function to extract ARP details from a given dataframe    
def extract_ARP_details(data):
    display(HTML("<h1 style='text-align:center; font-weight:bold;'>ARP Analysis</h1>"))
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
    # Create an arp_data dataframe from the input data
    # Filter the dataframe for rows where Protocol is 'ARP' and Info contains 'ARP'
    arp_data = data[(data['Protocol'] == 'ARP') & (data['Info'].str.contains('ARP')) | (data['Info'].str.contains('is at'))]
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

    # print the dictionary using a HTML table add the title 'IP and MAC Address Mapping' 
    display(HTML("<h2 style='text-align:center; font-weight:bold;'>IP and MAC Address Mapping</h2>"))
    display(HTML(pd.DataFrame(ip_mac_dict.items(), columns=['IP Address', 'MAC Address']).to_html(index=False, classes='table table-striped', border=0)))
    display(HTML("""
    <style>
    .table {
        margin-left: auto;
        margin-right: auto;
    }
    </style>
    """))
    return ip_mac_dict
    
    
# Function to combine all the protocol analysis functions

def protocol_analysis(data):
    display(HTML("<h1 style='text-align:center; font-weight:bold;'>Protocol Analysis</h1>"))
    plot_analysis('Protocol Distribution',data, 'Protocol')
    extracted_data = extract_TCP_details(data)
    Top10(extracted_data, 'Source_IP:TCP_Port', 'Source IP and TCP Port combinations')
    Top10(extracted_data[extracted_data['Source_Type'] == 'Private'], 'Source_IP:TCP_Port', 'Private Source IP and TCP Port combinations')
    Top10(extracted_data[extracted_data['Source_Type'] == 'Public'], 'Source_IP:TCP_Port', 'Public Source IP and TCP Port combinations')
    Top10(extracted_data, 'Destination_IP:TCP_Port', 'Destination IP and TCP Port combinations')
    Top10(extracted_data[extracted_data['Destination_Type'] == 'Private'], 'Destination_IP:TCP_Port', 'Private Destination IP and TCP Port combinations')
    Top10(extracted_data[extracted_data['Destination_Type'] == 'Public'], 'Destination_IP:TCP_Port', 'Public Destination IP and TCP Port combinations')
    plot_analysis('TCP Messages Distribution',extracted_data, 'TCP_Msg')
    plot_analysis('TCP Control Messages Distribution',extracted_data, 'TCP_Control_Msg')
    extract_ARP_details(data)

###############################################Data Analysis#############################################

# Function to perform data analysis
def data_analysis(data):
    data = data_preprocessing(data)
    source_analysis(data)
    destination_analysis(data)
    dns_analysis(data) # DNS Analysis - comment out if not needed
    protocol_analysis(data)
    
