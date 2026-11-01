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
                # I match the marker anywhere in the line, so a TODO inside a
                # string value counts as a comment finding. I also keep this
                # search case sensitive while the outdated search below ignores
                # case, so a lowercase todo passes and a lowercase deprecated
                # does not. That split is inherited, and I note it rather than
                # pretend the two searches behave the same.
                if re.search(r"(#|\/\/|\/\*)\s*(TODO|FIXME|XXX)", line):
                    # The full line goes into the warning, stripped but otherwise as
                    # written. A comment that itself quotes a credential is echoed
                    # back in my output, unlike the secret finder below, which
                    # redacts on purpose.
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

        if not content.strip():
            return [f"Error: Empty file: {filepath}. Nothing was analyzed."]

        if filetype == 'auto':
            # Attempt to auto-detect filetype based on extension
            if filepath.lower().endswith(('.yaml', '.yml')):
                filetype = 'yaml'
            elif filepath.lower().endswith('.json'):
                filetype = 'json'
            else:
                logging.warning("Could not auto-detect file type.  Analyzing as plain text.")
                # An unknown suffix gets comments only. The parsed checks below
                # never run for that file, and the only trace is the warning in
                # the log, so the printed results look thinner without saying
                # why unless the reader also reads the log.
                return analyze_comments(filepath) # Default to comment analysis if type is unknown

        # Comment analysis is the headline check, so it runs on parsed files too.
        # This reopens and rereads the file I already hold in content.
        # If the file changed between the two reads, the comment results
        # and the parsed results can describe different versions of it.
        # The error strings that function returns on failure also land
        # in this same list, mixed in with genuine findings.
        warnings.extend(analyze_comments(filepath))

        if filetype == 'yaml':
            try:
                data = yaml.safe_load(content)
                # Yaml Lint check
                try:
                    # I run yamllint without a check flag and read the return code
                    # myself, because lint output on stdout is a result I report
                    # either way. A missing binary is the only quiet path, handled
                    # in the except below; a failed lint with empty stdout still
                    # appends a warning whose body is blank.
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
                # The optional quotes cover the JSON form, where a quote sits
                # between the quoted key and the colon.
                # Twenty characters is my floor, and the allowed set excludes
                # dots and plus signs, so a short password and a token in a
                # format like a JWT both pass under this search. I am looking
                # for long plain values next to a known key name, nothing more.
                match = re.search(r"[\"']?(api_key|apikey|password|secret)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]{20,}[\"']?", line, re.IGNORECASE)
                if match:
                    # Report the location and the key name only. The matched
                    # value is never printed.
                    secrets_found.append(f"Potential secret found on line {i+1}: {match.group(1)}=<redacted>")
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
        # Any warning, secret, or error result is a finding, so the run
        # exits 1 and a calling script can gate on it.
        sys.exit(1)
    else:
        print("No issues found.")


if __name__ == "__main__":
    main()