import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


def is_termination_msg(content: Dict[str, Any]) -> bool:
    """Check if a message indicates termination."""
    return content.get("content", "").strip() == "TERMINATE" if content.get("content") is not None else False


def get_log(dbname="logs.db", table="chat_completions"):
    import sqlite3

    con = sqlite3.connect(dbname)
    query = f"SELECT * from {table}"
    cursor = con.execute(query)
    rows = cursor.fetchall()
    column_names = [description[0] for description in cursor.description]
    data = [dict(zip(column_names, row)) for row in rows]
    con.close()
    return data


def filter_and_sort_files_by_ip(dir_path: Path):
    """
    Filters the latest file for each IP address and sorts all files in descending order of their timestamp.

    Args:
        dir_path (str): Target subdirectory path.
        base_dir (Path): Base directory path.

    Returns:
        list[Path]: Latest sorted files, one per IP.
    """
    dir_files = list(dir_path.glob("*.txt"))

    if not dir_files:
        raise FileNotFoundError(f"No files found in directory: {dir_path}")

    def extract_metadata(file_path):
        """
        Extracts the timestamp and IP address from filename.

        Args:
            file_path (Path): The file path to process.

        Returns:
            tuple[datetime, str]: Tuple containing the extracted timestamp and IP address.
        """
        try:
            file_parts = file_path.stem.split("_")
            timestamp_str = "_".join(file_parts[2:-1])  # Extract timestamp parts
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d_%H-%M-%S")  # Convert to datetime
            ip = file_parts[-1]  # Extract the IP address
            return timestamp, ip
        except (ValueError, IndexError) as e:
            print(f"Error processing file {file_path}: {e}")
            return datetime.min, None

    # Extract metadata and sort files by timestamp in descending order
    files_with_metadata = [
        (file_path, *extract_metadata(file_path)) for file_path in dir_files
    ]
    sorted_files = sorted(
        filter(lambda x: x[2] is not None, files_with_metadata),  # Valid IP filter
        key=lambda x: x[1],  # Sort by timestamp
        reverse=True,
    )

    # Keep only the latest file for each IP
    latest_files_by_ip = {}
    for file_path, timestamp, ip in sorted_files:
        if ip not in latest_files_by_ip:
            latest_files_by_ip[ip] = file_path

    # Return the latest files sorted by timestamp
    return sorted(list(latest_files_by_ip.values()), key=lambda x: extract_metadata(x)[0], reverse=True)


def ip_in_subnet(ip, subnet):
    ip_obj = ipaddress.ip_address(ip)
    subnet_obj = ipaddress.ip_network(subnet, strict=False)
    return ip_obj in subnet_obj
