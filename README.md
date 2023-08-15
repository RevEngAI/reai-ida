# RevEng.AI IDA Plugin

This documentation provides steps to install the RevEng.AI plugin for IDA on ARM-based macOS devices, particularly the M series chips.

## Installation on ARM macOS (M series chips)

Since IDA Pro utilizes the in-built macOS python version (still x86_64 for ARM architecture) for its IDAPython scripts, it's necessary to determine the correct python path and install the python packages in the x86_64 architecture.

### Steps:

1. **Locate the Python Interpreter in IDA Pro:** 
   - Navigate to `IDA app path/Contents/MacOS/idapyswitch`.
   - The path should resemble `/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.x/Python3`.

2. **Clone the RevEng.AI Package:**
   - Execute: 
     ```
     git clone [reait-repo-link] /path/to/reait_repo
     ```

3. **Switch to Python Bin Directory:** 
   - In a new terminal window, navigate to `/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.x/bin`.

4. **Build the RevEng.AI Package:** 
   - Execute: 
     ```
     arch -x86_64 ./python3.x -m build /path/to/reait_repo
     ```

5. **Install the RevEng.AI Package:**
   - Execute: 
     ```
     arch -x86_64 ./python3.x -m pip install -U ~/RevEng.AI/reait/dist/reait-0.0.16-py3-none-any.whl
     ```

> **Note:** Make sure to replace `[reait-repo-link]` with the actual link to the repository.
