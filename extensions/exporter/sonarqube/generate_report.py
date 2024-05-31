import json
import requests

def get_sonarqube_data(url, api_key, access_token, params, data_array_names, total_key="total", page_key="p", page_size_key="ps"):
    """
    Fetches data from a SonarQube API endpoint with paging and merges results into a list.

    Args:
        url (str): The base URL of the SonarQube API endpoint.
        api_key (str): Your SonarQube Server API key.
        access_token (str): Your SonarCloud access token.
        params (dict): Dictionary of query parameters for the API request.
        data_array_names (str): Names of the list in the JSON structure to store retrieved data.
        total_key (str, optional): Key in the JSON response indicating the total number of elements (default: "total").
        page_key (str, optional): Key in the response for the current page number (default: "p").
        page_size_key (str, optional): Key in the response for the page size (default: "ps").

    Returns:
        list: A list containing all retrieved data from the paginated API response.
    """

    page = 1
    ps = params.get(page_size_key, 100)  # Default page size of 100

    data = []
    data = {data_array_name: [] for data_array_name in data_array_names} # Initialize the data array

    while True:
        params.update({page_key: page})
        headers = None
        if bearer_token is not None:
            auth = None
            headers = {'Accept': 'application/json', 'Authorization': 'Bearer {}'.format(access_token)}
        else:
            auth = requests.auth.HTTPBasicAuth(api_key, "")

        print(f"Retrieving {url}... page {page}...")
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()  # Raise an exception for non-200 status codes

        json_data = response.json()
        for data_array_name in data_array_names:
            print(f"Retrieving {data_array_name}... length: {len(json_data.get(data_array_name, []))}")
            data[data_array_name].extend(json_data.get(data_array_name, [])) # Merge the retrieved data into the data array

        total_elements = json_data.get(total_key)
        print(f"Page {page} retrieved of total {total_elements}.")

        if total_elements is None or page * ps >= total_elements:
            break

        page += 1

    return data

def build_json_from_sonarqube(sonarqube_url, api_key, bearer_token, project_key):
    """
    Builds a JSON structure with issues, hotspots, rules, and components from SonarQube or SonarCloud APIs.

    Args:
        sonarqube_url (str): Base URL of your SonarQube server or SonarCloud url (https://sonarcloud.io).
        api_key (str): Your SonarQube API key.
        bearer_token (str): Your SonarCloud access token.
        project_key (str): Key of the project to query.

    Returns:
        dict: A dictionary containing the constructed JSON structure.
    """

    issues_params = {
        "componentKeys": project_key,
        "impactSoftwareQualities" : "SECURITY",  # Only security issues
        "additionalFields": "_all"
    }
    hotspots_params = {
        "projectKey": project_key
    }
    issues_data = get_sonarqube_data(f"{sonarqube_url}/api/issues/search", api_key, bearer_token, issues_params, ["issues", "rules", "components"])
    hotspots_data = get_sonarqube_data(f"{sonarqube_url}/api/hotspots/search", api_key, bearer_token, hotspots_params, ["hotspots","components"])

    components = issues_data.get("components")
    # Merge hotspots components
    components.extend(hotspots_data.get("components"))

    # Remove duplicates components
    components_keys = []
    components_without_duplicates = []
    for component in components:
        if component["key"] not in components_keys:
            components_without_duplicates.append(component)
            components_keys.append(component["key"])

    json_data = {
        "issues": issues_data.get("issues"),
        "hotspots": hotspots_data.get("hotspots"),
        "rules": issues_data.get("rules"),
        "components": components_without_duplicates
    }

    print(f"total issues {len(json_data.get('issues'))}")
    print(f"total hotspots {len(json_data.get('hotspots'))}")
    print(f"total components {len(json_data.get('components'))}")
    print(f"total rules {len(json_data.get('rules'))}")

    return json_data

def save_json_to_file(json_data, filename):
    """
    Saves the JSON data to a file.

    Args:
        json_data (dict): The JSON data structure to save.
        filename (str): The filename to use for saving the data.
    """

    with open(filename, "w") as outfile:
        json.dump(json_data, outfile, indent=4)  # Add indentation for readability

# Replace with your SonarQube details
#sonarqube_url = "https://your-sonarqube-server" or "https://sonarcloud.io"
#api_key = "your-api-key" # For SonarQube
#bearer_token = "your-bearer-token" # For SonarCloud
#project_key = "your-project-key"

json_data = build_json_from_sonarqube(sonarqube_url, api_key, bearer_token, project_key)
save_json_to_file(json_data, "sonarqube.report.json")

print("SonarQube data saved to sonarqube_data.json")
