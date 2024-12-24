import os
from pathlib import Path
from typing import Dict, Any

from dotenv import load_dotenv


def load_llm_config(base_dir: Path) -> Dict[str, Any]:
    env_path = base_dir / ".env"
    load_dotenv(dotenv_path=env_path, verbose=True, override=True)

    # LLM Configuration
    llm_config: Dict[str, Any] = {
        "config_list": [
            {
                "model": os.getenv("LLM_MODEL", "gpt-4o"),
                "api_type": os.getenv("LLM_API_TYPE", "azure"),
                "api_key": os.getenv("LLM_API_KEY"),
                "api_version": os.getenv("LLM_API_VERSION", "2024-02-01"),
                "azure_endpoint": os.getenv("LLM_AZURE_ENDPOINT"),
            }
        ],
    }
    return llm_config
