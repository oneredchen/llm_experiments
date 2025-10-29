import os
import json
import ollama
from utils.ioc_extraction_workflow import ioc_extraction_agent_workflow
import logging
from logging_config import setup_logging
from dotenv import load_dotenv

STATE_FILE = "test_state.json"


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {"last_model_index": -1, "last_case_index": -1}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)


def main():
    """
    Main function to run the test workflow.
    """
    load_dotenv()
    ollama_host = os.getenv("OLLAMA_HOST")
    setup_logging("test.log")
    logger = logging.getLogger(__name__)

    # Create test results directory
    if not os.path.exists("test_results"):
        os.makedirs("test_results")

    # Get LLM models from Ollama
    try:
        client = ollama.Client(host=ollama_host)
        models = [model["model"] for model in client.list()["models"]]
    except Exception as e:
        logger.error(f"Could not connect to Ollama to get models: {e}")
        return

    # Get case files
    case_files = sorted([f for f in os.listdir("cases") if f.endswith(".txt")])

    state = load_state()
    last_model_index = state.get("last_model_index", -1)
    last_case_index = state.get("last_case_index", -1)

    start_model_index = last_model_index if last_model_index != -1 else 0

    for model_index in range(start_model_index, len(models)):
        model = models[model_index]

        start_case_index = 0
        if model_index == last_model_index:
            start_case_index = last_case_index + 1

        for case_index in range(start_case_index, len(case_files)):
            case_file = case_files[case_index]
            case_number = os.path.splitext(case_file)[0].split("_")[1]
            test_name = f"test-{case_number}-{model.replace(':', '_')}"
            output_file = f"test_results/{test_name}.json"

            logger.info(f"Running test: {test_name}")

            with open(os.path.join("cases", case_file), "r") as f:
                incident_description = f.read()

            try:
                result = ioc_extraction_agent_workflow(
                    llm_model=model,
                    case_id=case_number,
                    incident_description=incident_description,
                    ollama_host=ollama_host,
                )

                # Convert Pydantic models to dicts
                if result.get("host_ioc_objects"):
                    result["host_ioc_objects"] = [
                        ioc.model_dump() for ioc in result["host_ioc_objects"]
                    ]
                if result.get("network_ioc_objects"):
                    result["network_ioc_objects"] = [
                        ioc.model_dump() for ioc in result["network_ioc_objects"]
                    ]
                if result.get("timeline_objects"):
                    result["timeline_objects"] = [
                        event.model_dump() for event in result["timeline_objects"]
                    ]

                # Convert datetime objects to strings
                def default_serializer(o):
                    if hasattr(o, "isoformat"):
                        return o.isoformat()
                    raise TypeError(
                        f"Object of type {o.__class__.__name__} is not JSON serializable"
                    )

                with open(output_file, "w") as f:
                    json.dump(result, f, indent=4, default=default_serializer)

                logger.info(f"Test {test_name} completed successfully.")

                # Save state
                save_state(
                    {"last_model_index": model_index, "last_case_index": case_index}
                )

            except Exception as e:
                logger.error(f"Test {test_name} failed: {e}")
                # Save state up to the failed test
                save_state(
                    {"last_model_index": model_index, "last_case_index": case_index - 1}
                )
                return  # Stop execution on failure

    # Reset state after all tests are completed
    save_state({"last_model_index": -1, "last_case_index": -1})
    logger.info("All tests completed successfully.")


if __name__ == "__main__":
    main()
