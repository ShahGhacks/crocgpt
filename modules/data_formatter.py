import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Optional, List, Tuple

from .CONSTANTS import CommonPorts, NmapFeatures, PORT_FEATURE_MAPPING


def extract_data_by_port(
        grouped_output: List[Dict[str, List[List[str]]]],
        port_mapping: Dict[CommonPorts, List[NmapFeatures]]
) -> Dict[str, List[Dict[str, str]]]:
    """
    Extracts data from Nmap grouped output by port and subblocks, based on port-feature mapping.

    Args:
        grouped_output (List[Dict[str, List[List[str]]]]):
            Grouped Nmap output with ports as keys and subblocks of data.
        port_mapping (Dict[CommonPorts, List[NmapFeatures]]):
            Mapping of ports to their associated features.

    Returns:
        Dict[str, List[Dict[str, Dict[str, Optional[str]]]]]:
            A dictionary where keys are port names, and values are lists of feature data for each subblock.
    """
    extracted_data = {}

    for port_data in grouped_output:
        port_line = port_data["port"]  # Get the port line
        subblocks = port_data["subblocks"]  # Get the subblocks for this port

        # Identify the port in the mapping
        port = next((p for p in port_mapping if p.value in port_line), None)
        if not port:
            continue  # Skip if the port is not in the mapping

        # Extract features for each subblock
        port_features = []
        for subblock in subblocks:
            feature_data = {}
            for feature in port_mapping[port]:
                if any(line for line in subblock if feature.value in line):
                    if feature.value == NmapFeatures.PORT_20_21_FTP_VULNERS.value:
                        feature_data["VULNERABILITIES"] = "\n".join(subblock)
                    else:
                        feature_data[feature.name] = "\n".join(subblock)
            if feature_data:
                port_features.append(feature_data)

        # Store the extracted data for the port
        extracted_data[port.name] = port_features

    return extracted_data


def group_nmap_output_by_script(file_path: Path) -> List[Dict[str, List[List[str]]]]:
    """
    Groups Nmap scan output by port and then divides each port group into subblocks of information.

    Args:
        file_path (Path): Path to the Nmap scan output file.

    Returns:
        List[Dict[str, List[List[str]]]]: A list of dictionaries with each port's key
                                          containing subblocks for the port.
    """
    # Define the regex to identify port blocks (lines like "80/tcp")
    port_regex = re.compile(r"^\d+/tcp")  # Match lines that start with "80/tcp", "443/tcp", etc.

    # Read the file and collect lines
    with file_path.open("r") as file:
        lines = file.readlines()

    grouped_blocks = []  # List to store groups by ports
    current_block = []  # Temporary variable to track the current block of port + lines

    # Step 1: Split file into groups by port lines (e.g., "80/tcp")
    for line in lines:
        if port_regex.match(line):  # If a port line is matched
            if current_block:  # Append the existing block to grouped blocks
                grouped_blocks.append(current_block)
            current_block = [line.strip()]  # Start a new block with the current port line
        else:
            current_block.append(line.strip())  # Add non-port lines to current block

    if current_block:  # Add the last block if not empty
        grouped_blocks.append(current_block)

    # Step 2: Split each port block into subblocks based on "|_" lines
    port_output = []

    for block in grouped_blocks:
        # First line is the port line
        port_line = block[0]

        # Subdivide the block into subblocks
        subblocks = []  # Subblocks for this port
        current_subblock = []  # Temporary subblock storage

        for line in block[1:]:  # Start after the port line
            if line.startswith("|_"):  # End of a subblock
                current_subblock.append(line)  # Add the "|_" line
                subblocks.append(current_subblock)  # Save the completed subblock
                current_subblock = []  # Reset for the next subblock
            else:
                current_subblock.append(line)  # Collect lines for the current subblock

        # If any remaining subblock exists, add it
        if current_subblock:
            subblocks.append(current_subblock)

        # Add the final structure for this port
        port_output.append({
            "port": port_line,
            "subblocks": subblocks
        })

    return port_output


# Parsing the vulnerabilities
def parse_vulnerabilities(port_data: Dict[str, List[Dict[str, Dict[str, str]]]],
                          threshold: float = 0.4) -> List[Tuple[str, float, str]]:
    """
    Parses vulnerabilities from the extracted data.

    Args:
        port_data (Dict[str, List[Dict[str, Dict[str, str]]]]): Extracted port data.

    Returns:
        List[Tuple[str, float, str]]: A list of tuples with (ID, CVSS, URL).
    """

    vuln_regex = re.compile(r"(\S+)\s+(\d+\.\d+)\s+(\S+)")

    for port, scripts in port_data.items():
        for script_data in scripts:
            for feature, output in script_data.items():
                if feature == "VULNERABILITIES" and output:
                    # Extract vulnerabilities from the feature output
                    vulnerabilities = extract_vulnerabilities_from_output(vuln_regex, output)

                    # Group vulnerabilities by CVSS if any found
                    if vulnerabilities:
                        grouped_vulnerabilities = group_vulnerabilities_by_cvss(vulnerabilities, threshold)

                        # Update the current feature with grouped data
                        script_data[feature] = grouped_vulnerabilities

    return port_data


def extract_vulnerabilities_from_output(vuln_regex: re.Pattern, output: str) -> List[Tuple[str, float, str]]:
    """
    Extracts vulnerabilities from raw output using a regex pattern.

    Args:
        vuln_regex (re.Pattern): Compiled regex pattern to match vulnerabilities.
        output (str): Raw output string to parse vulnerabilities.

    Returns:
        List[Tuple[str, float, str]]: A list of tuples (vuln_id, cvss_score, url).
    """
    vulnerabilities = []

    for line in output.splitlines():
        match = vuln_regex.search(line)
        if match:
            vuln_id, cvss_score, url = match.groups()
            vulnerabilities.append((vuln_id, float(cvss_score), url))

    return vulnerabilities


def group_vulnerabilities_by_cvss(
        vulnerabilities: List[Tuple[str, float, str]], threshold: float
) -> Dict[float, List[Tuple[str, float, str]]]:
    """
    Groups vulnerabilities by CVSS scores in descending order, removing those below the threshold.

    Args:
        vulnerabilities (List[Tuple[str, float, str]]): List of vulnerabilities.
        threshold (float): The minimum CVSS score to include vulnerabilities.

    Returns:
        Dict[float, List[Tuple[str, float, str]]]: Dictionary grouped by CVSS scores.
    """
    grouped_by_cvss = defaultdict(list)

    # Filter and sort vulnerabilities by CVSS scores in descending order
    filtered_vulnerabilities = filter(lambda x: x[1] >= threshold, vulnerabilities)
    sorted_vulnerabilities = sorted(filtered_vulnerabilities, key=lambda x: x[1], reverse=True)

    # Group vulnerabilities by their CVSS scores
    for vuln in sorted_vulnerabilities:
        grouped_by_cvss[vuln[1]].append(vuln)

    return dict(grouped_by_cvss)  # Convert defaultdict to a standard dictionary before returning


def save_results_to_file(results: Dict[float, List[Tuple[str, float, str]]], output_path: Path) -> None:
    """
    Saves the grouped vulnerabilities to a file.

    Args:
        results (dict): Grouped vulnerabilities by CVSS score.
        output_path (Path): File path to save the results.
    """
    try:
        with open(output_path, "w") as f:
            for cvss, vulns in results.items():
                f.write(f"CVSS Score: {cvss}\n")
                for vuln_id, score, url in vulns:
                    f.write(f"    ID: {vuln_id}\n")
                    f.write(f"    URL: {url}\n")
                    f.write(f"    SCORE: {score}\n")
                f.write("-" * 40 + "\n")
        print(f"Results saved to {output_path}")
    except IOError as e:
        print(f"Error saving results to file: {e}")


def get_refined_results(file_path: Path, threshold: float = 0.4):
    # Check if file exists
    if not file_path.exists():
        print(f"Error: File not found at {file_path}")
        exit(1)

    # Step 1: Group and parse the Nmap output
    grouped_output = group_nmap_output_by_script(file_path)

    # Extract data by port
    port_data = extract_data_by_port(grouped_output, PORT_FEATURE_MAPPING)
    refined_data = parse_vulnerabilities(port_data, threshold)
    return refined_data


if __name__ == "__main__":
    # file_path = Path("/home/rev9-ai/projects/cyber-agent/src/results/nmap_scan_2024-12-21_16-41-20_192.168.100.56.txt")
    file_path = Path("/src/results/nmap_scan_2024-12-23_07-53-12_192.168.100.55.txt")

    # Check if file exists
    if not file_path.exists():
        print(f"Error: File not found at {file_path}")
        exit(1)
    results = get_refined_results(file_path)
    # # Optional: Save the results to a file
    # output_path = file_path.with_suffix(".parsed.txt")
    # save_results_to_file(grouped_vulnerabilities, output_path)
    # print(f"Grouped vulnerabilities saved to {output_path}")
