import argparse
import logging
import os
import re
import json
import yaml
import subprocess
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes configuration files for potentially sensitive information or outdated comments.")
    parser.add_argument("filepath", help="Path to the configuration file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    parser.add_argument("-t", "--filetype", choices=['yaml', 'json', 'auto'], default='auto', help="Specify the file type (yaml, json, auto).  'auto' will attempt to determine the type.")

    # Add offensive tool related arguments (example)
    parser.add_argument("--find-secrets", action="store_true", help="Attempt to find potential secrets in the file (e.g., API keys, passwords).")

    return parser.parse_args()


def analyze_comments(filepath):
    """
    Analyzes comments in a file for potential issues.

    Args:
        filepath (str): The path to the file.

    Returns:
        list: A list of warnings/errors found in the comments.
    """
    warnings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                # Look for "TODO", "FIXME", "XXX" in comments
                if re.search(r"(#|\/\/|\/\*)\s*(TODO|FIXME|XXX)", line):
                    warnings.append(f"Warning: Potential TODO/FIXME/XXX found on line {i+1}: {line.strip()}")

                # Look for common phrases indicating outdated comments
                if re.search(r"(#|\/\/|\/\*)\s*(deprecated|obsolete|old)", line, re.IGNORECASE):
                     warnings.append(f"Warning: Potential outdated comment found on line {i+1}: {line.strip()}")


    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return ["Error: File not found."]
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        return ["Error: Failed to read file."]

    return warnings



def analyze_file_content(filepath, filetype='auto'):
    """
    Analyzes the file content for potential misconfigurations.

    Args:
        filepath (str): The path to the file.
        filetype (str): The type of file (yaml, json, auto).

    Returns:
        list: A list of warnings/errors found in the file.
    """
    warnings = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        if filetype == 'auto':
            # Attempt to auto-detect filetype based on extension
            if filepath.lower().endswith(('.yaml', '.yml')):
                filetype = 'yaml'
            elif filepath.lower().endswith('.json'):
                filetype = 'json'
            else:
                logging.warning("Could not auto-detect file type.  Analyzing as plain text.")
                return analyze_comments(filepath) # Default to comment analysis if type is unknown

        if filetype == 'yaml':
            try:
                data = yaml.safe_load(content)
                # Yaml Lint check
                try:
                    result = subprocess.run(['yamllint', filepath], capture_output=True, text=True)
                    if result.returncode != 0:
                        warnings.append(f"yamllint found issues:\n{result.stdout}")
                    elif result.stdout:
                        warnings.append(f"yamllint reported:\n{result.stdout}")
                except FileNotFoundError:
                    logging.warning("yamllint not found.  Skipping yamllint checks.")

                # Example YAML specific check (replace with your own logic)
                if isinstance(data, dict) and 'api_version' in data:
                    if data['api_version'] == 'v1':
                        warnings.append("Warning: api_version is v1, consider upgrading to a newer version.")
            except yaml.YAMLError as e:
                warnings.append(f"Error parsing YAML: {e}")

        elif filetype == 'json':
            try:
                data = json.loads(content)
                # Json Lint check
                try:
                    result = subprocess.run(['jsonlint', filepath], capture_output=True, text=True)
                    if result.returncode != 0:
                        warnings.append(f"jsonlint found issues:\n{result.stderr}")  # jsonlint writes errors to stderr
                    elif result.stdout:
                         warnings.append(f"jsonlint reported:\n{result.stdout}")


                except FileNotFoundError:
                    logging.warning("jsonlint not found.  Skipping jsonlint checks.")

                # Example JSON specific check (replace with your own logic)
                if isinstance(data, dict) and 'debug' in data and data['debug'] is True:
                    warnings.append("Warning: Debug mode is enabled. Disable in production.")

            except json.JSONDecodeError as e:
                warnings.append(f"Error parsing JSON: {e}")
        else:
            warnings.append("Error: Invalid filetype specified.")

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return ["Error: File not found."]
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        return ["Error: Failed to read file."]

    return warnings



def find_secrets(filepath):
    """
    Attempts to find potential secrets in the file.
    This is a simplified example and should be expanded for real-world use.
    """
    secrets_found = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                # Basic regex for API keys (extend this!)
                if re.search(r"(api_key|apikey|password|secret)\s*[:=]\s*[\"']?[a-zA-Z0-9_-]{20,}[\"']?", line, re.IGNORECASE):
                    secrets_found.append(f"Potential secret found on line {i+1}: {line.strip()}")
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return ["Error: File not found."]
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        return ["Error: Failed to read file."]

    return secrets_found


def main():
    """
    Main function to execute the configuration analysis.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    # Input validation:  Check file exists
    if not os.path.exists(args.filepath):
        logging.error(f"File not found: {args.filepath}")
        print(f"Error: File not found: {args.filepath}")
        sys.exit(1)

    # Analyze the file
    analysis_results = analyze_file_content(args.filepath, args.filetype)

    # Offensive tools - Run secret finding if requested
    if args.find_secrets:
        secrets = find_secrets(args.filepath)
        analysis_results.extend(secrets)


    if analysis_results:
        print("Analysis Results:")
        for result in analysis_results:
            print(result)
    else:
        print("No issues found.")


if __name__ == "__main__":
    main()