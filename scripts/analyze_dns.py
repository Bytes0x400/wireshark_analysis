# This is the file with the DNS resolution functions

# Importing the necessary libraries
import matplotlib.pyplot as plt
import requests
import pandas as pd
import os



#########################################################################DNS Analysis#########################################################################
# Function to extract unique destination addresses from the data for DNS resolution
def unique_destination_addresses(data):
    unique_destinations = data['Destination'].unique()
    unique_destinations = [destination for destination in unique_destinations if destination != '255.255.255.255']
    return unique_destinations


#Function to build the API URL and key for DNS resolution
def build_api_url_and_key():
    """
    Constructs the API URL and retrieves the API key from environment variables.

    This function builds the base URL for the DriftNet API and fetches the API key
    from the environment variable 'DRIFTNET_KEY'. The URL is used for reverse DNS
    lookups by appending an IP address to it.

    Returns:
        tuple: A tuple containing the base API URL (str) and the API key (str).

    Example:
        api_url, api_key = build_api_url_and_key()
        # api_url -> 'https://api.driftnet.io/v1/domain/rdns?ip='
        # api_key -> 'your_api_key_here'
    """
    api_url = 'https://api.driftnet.io/v1/domain/rdns?ip='
    api_key = os.getenv('DRIFTNET_KEY')
    return api_url, api_key


# Function to identify nested dictionaries within a given dictionary
def identify_nested_dictionaries(data):
    """
    Identify nested dictionaries within a given dictionary.
    This function takes a dictionary where some values may be lists containing dictionaries.
    It identifies these nested dictionaries and returns them in a new dictionary with keys
    indicating their position in the original structure.
    Args:
        data (dict): The input dictionary to be analyzed.
    Returns:
        dict: A dictionary containing the nested dictionaries found in the input data.
              The keys are strings representing the path to the nested dictionaries in the
              format "key[index]".
    Example:
        >>> data = {
        ...     'dns_query': [{'context': 'dns-ns', 'value': 'ns1.example.com'}, {'context': 'dns-ns', 'value': 'ns2.example.com'}],
        ...     'other_data': [1, 2, {'context': 'dns-ns', 'value': 'ns3.example.com'}],
        ...     'irrelevant': 'string'
        ... }
        >>> identify_nested_dictionaries(data)
        {'dns_query[0]': {'context': 'dns-ns', 'value': 'ns1.example.com'}, 'dns_query[1]': {'context': 'dns-ns', 'value': 'ns2.example.com'}, 'other_data[2]': {'context': 'dns-ns', 'value': 'ns3.example.com'}}
    """
    nested_dicts = {}
    
    for key, value in data.items():
        if isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    nested_dicts[f"{key}[{index}]"] = item
    return nested_dicts


# Function to extract DNS NS (Name Server) values from the provided data and associate them with the given source IP
def extract_dns_ns_values(source_ip, data):
    """
    Extract DNS NS (Name Server) values from the provided data and associate them with the given source IP.
    Args:
        source_ip (str): The source IP address to associate with the extracted DNS NS values.
        data (dict): A dictionary containing the data to be processed. The dictionary is expected to have a structure where
                     each key maps to another dictionary that may contain an 'items' key. The 'items' key maps to a list of
                     dictionaries, each of which may contain a 'context' key with the value 'dns-ns' and a 'value' key with
                     the DNS NS value to be extracted.
    Returns:
        dict: A dictionary with the source IP as the key and a list of extracted DNS NS values as the value.
    Example:
        data = {
            'entry1': {
                'items': [
                    {'context': 'dns-ns', 'value': 'ns1.example.com'},
                    {'context': 'dns-ns', 'value': 'ns2.example.com'}
                ]
            },
            'entry2': {
                'items': [
                    {'context': 'dns-ns', 'value': 'ns3.example.com'}
                ]
            }
        }
        source_ip = '192.168.1.1'
        result = extract_dns_ns_values(source_ip, data)
        # result will be {'192.168.1.1': ['ns1.example.com', 'ns2.example.com', 'ns3.example.com']}
    """
    extracted_values = []
    result_dict = {}
    
    for key, value in data.items():
        if 'items' in value: # check if the key has an 'items' key
            for item in value['items']:
                if isinstance(item, dict) and item.get('context') == 'dns-ns': # check if the item is a dictionary and has a 'context' key with a value of 'dns-ns'
                    if item.get('value') not in extracted_values: # check if the value is not already in the list
                        extracted_values.append(item.get('value')) # append the value to the list
                
    result_dict = {source_ip: extracted_values} # create a dictionary with the source IP as the key and the extracted values as the value
    return result_dict 



# Function to resolve DNS for a list of sources, count the occurrences of unique domains, and plot a pie chart
def dns_resolution_and_value_counts(source_list):
    """
    Resolves DNS for a list of sources, counts the occurrences of unique domains, and plots a pie chart.
    Parameters:
    source_list (list): A list of source IP addresses or domain names to resolve.
    Returns:
    tuple: A tuple containing:
        - rDNS_dict (dict): A dictionary with resolved DNS values for each source.
        - rDNS_error (dict): A dictionary with sources that encountered errors and their corresponding status codes.
        - unique_domains (list): A list of unique domain names extracted from the resolved DNS values.
        - value_counts (pd.Series): A pandas Series containing the counts of each unique domain, with a category "Others" for domains with counts less than 4.
    The function performs the following steps:
    1. Builds the API URL and key for DNS resolution.
    2. Iterates over the source list and makes API requests to resolve DNS.
    3. Identifies nested dictionaries in the API response and extracts DNS NS values.
    4. Updates the rDNS_dict with the resolved DNS values and logs any errors in rDNS_error.
    5. Extracts unique domain names from the resolved DNS values.
    6. Counts the occurrences of each unique domain.
    7. Aggregates domains with counts less than 4 into a category called "Others".
    8. Plots a pie chart of the external domains being accessed from the network.
    """
    api_url, api_key = build_api_url_and_key()
    rDNS_dict = {}
    rDNS_error = {}
    
    for source in source_list:
        api_response = requests.get(
            api_url + source,
            headers={
                'Authorization': f'Bearer {api_key}'
            }
        )
        if api_response.status_code == 200:
            response_json = api_response.json()
            nested_dicts = identify_nested_dictionaries(response_json)
            dns_ns_values = extract_dns_ns_values(source, nested_dicts)
            rDNS_dict.update(dns_ns_values)
        else:
            rDNS_error[source] = api_response.status_code

    # Get the unique domain names from the rDNS values
    unique_domains = []
    list_of_domains = []
    for key, value in rDNS_dict.items():
        for item in value:
            sub_domain = item.split('.')[-3]
            domain = item.split('.')[-2]
            top_level_domain = item.split('.')[-1]
            domain_entry = sub_domain + '.' + domain + '.' + top_level_domain
            list_of_domains.append(domain_entry)
            if domain_entry not in unique_domains:
                unique_domains.append(domain_entry)
    
    # Get the value counts for the list of domains
    value_counts = pd.Series(list_of_domains).value_counts()
    # Create a new domain category called "Others" and add all the value_counts of 4 or less to it
    others_count = value_counts[value_counts < 4].sum()
    value_counts = value_counts[value_counts >= 4]
    value_counts['Others'] = others_count
  
    # plot a pie chart of the external domains being accessed from the network
    plt.figure(figsize=(12, 6))
    plt.title('External Domains being accessed from the network')
    plt.pie(value_counts, labels=value_counts.index, autopct='%1.2f%%', startangle=90)
    # Save the plot in the 'graphics' folder
    plt.show()
    return rDNS_dict, rDNS_error, unique_domains, value_counts

def dns_analysis(data):
    data = data[data['Destination_Type'] == 'Public']
    dns_resolution_and_value_counts(unique_destination_addresses(data))