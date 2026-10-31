![Banner](banner.png)

# misconfig-ConfigCommentAnalyzer
Analyzes configuration files for potentially sensitive information or outdated comments that may reveal vulnerabilities or misunderstandings about the configuration. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-configcommentanalyzer`

## Usage
`./misconfig-configcommentanalyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-t`: No description provided
- `--find-secrets`: Scan for secret shaped assignments, in plain form (`api_key: value`) and in the JSON form (`"password": "value"`). A finding reports the line number and the key name with the value shown as `<redacted>`. The matched value itself is never printed.

## Behavior and exit codes
- Comment analysis runs on every input, YAML and JSON files included, not only on files with an unknown extension.
- Exit 0: no issues found in a file that was read and analyzed.
- Exit 1: any warning, secret finding, or error result, and also a missing input path. A parse error and a directory given as the input are error results at exit 1.
- An empty file is an error at exit 1. It is not reported as a file with no issues.

## License
Copyright (c) ShadowStrikeHQ
