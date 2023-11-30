# RevEng.AI IDA PRO Plugin

IDA PRO Plugin for RevEng.AI

### Supported Functionality:

- Uploading of binaries for analysis to RevEng.AI platform
- Renaming of function names given with similar binaries
- Configuration and persistence of plugin configuration (API key, host, port and model selection)
- Function explanations (currently stub code only)

### In-progress
- File auto-analysis

# Install
Copy revengai dir and revengai.py to the `plugins` dir inside IDA Pro installation dir

# Troubleshooting
- Logging goes out to the `Output` windows and written to log file. 
- Configurations persisted to `%TEMP%\revengai` dir


# TODO
- Potentially update configuration/log file writing location to a new place using IDA api.
- Filter function ANN using confidence slider
- Add ability to get status for a given analysis
- Function explanation
- Update README with screenshots etc


