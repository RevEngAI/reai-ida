# <img src="./revengai/resources/logo.png" width=20> RevEng.AI IDA Pro Plugin

IDA Pro Plugin for [RevEng.AI](https://reveng.ai/).

### Features Supported

Below a non-exhaustive list of the features supported by the plugin:
- Uploading of binaries for analysis to RevEng.AI platform
- Downloading logs for analysis from RevEng.AI platform
- Removing analysis from RevEng.AI platform
- Renaming of function names given with similar binaries
- Generates AI summaries for the analysed function
- Synchronise all functions with differing names between the local analysis and the RevEng.AI platform
- Configuration and persistence of plugin configuration (personal API key, host and analysis)
- …

# Installation & Running 🚀

Install the required Python libraries: `pip install -r requirements.txt`. Copy `revengai` dir and `reveng.py` to the `plugins` dir inside IDA Pro installation dir (or `~/.idapro/plugins` on MacOS and Linux).

### Details

Check the version of Python your IDA Pro installation is using by opening IDA and running `sys.path` inside the Python console. You need to ensure that the dependencies are installed by the version of Python IDA is using. You can then run `{{path to python version}} -m pip install -r requirements.txt`. For example, `$ /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -m pip install -r requirements.txt`

### Development

Ensure the latest version of the [reait](https://github.com/RevEngAI/reait/releases) package is installed with the version of Python IDA is using.

## Setup & Usage 📦

Open IDA and if the plugin has loaded successfully it should be visible under `RevEng.AI` menu.

![menu](./assets/img/1.png)

If `RevEng.AI` menu does not appear in the menubar, you can:
- either click on <img src="revengai/resources/favicon.png" width="16"/> displayed in the toolbar
- or click on `Edit > Plugins` then `RevEng.AI`

![plugin](./assets/img/13.png)

Before using the plugin, it needs to be configured. Select `Run Setup Wizard` from the menu shown in the previous image.

A popup should appear that contains the main configuration window for the plugin like below:

![configuration](./assets/img/2.png)

Fill in the API key and host information - the model drop-down will automatically populate when clicked on `Continue`. This only works if the entered configuration information is valid.

Once this is done you are now ready to use the plugin.

## Uploading Files

Before we do any analysis we need to upload a file. Uploading a file is available via the IDA Views of the code or from the pseudocode window by right-clicking.

![upload_file](./assets/img/3.png)

Select `Process Binary`, it will automatically ask whether you want analysis to be done on the file. Currently the analysis does not support customisation but will in the future.

![analyse_file](./assets/img/11.png)

Once the file has been sent for analysis, an analysis ID is automatically set internally so any future actions that are specific to an analysis will use this ID.

You can check the status of your request by selecting `Check Analysis Status` from either of the menus like before.

The status of any previous analysis done can be viewed by selecting `Binary Analysis History` from the popup menu, an example of this menu is in the next screenshot.

![select_file](./assets/img/4.png)

**A right click allows you to delete, view analysis report or set as current analysis for the selected analysis**

## Binary Synchronisation

When a previously analysed binary is selected, a popup-window is displayed, prompting you to synchronise all local functions whose name differs from that present on the RevEng.AI platform. 

![auto_sync](./assets/img/12.png)

**A right click allows you to sync, jump to or breakdown the selected function**

## Function Renaming

#### Rename a Function

Right-clicking on any function name in an IDA View and selecting `Rename From Similar Functions` will bring up the following window that lets you rename a function.

![rename_function_menu](./assets/img/5.png)

Currently, all available functions from all binaries are displayed in order of similarity confidence. The user is able to filter on both binary and confidence levels

![rename_function_dialog](./assets/img/6.png)

Selecting an entry from the list and then pressing `Rename` will cause the function to be renamed within IDA.

**A right click allows you to rename or breakdown the selected function**

#### Analyse Binary

You can also batch analyse the binary to rename functions using the `Analyse Binary`.

![auto_analyze_menu](./assets/img/7.png)

This tool pull the list of collections you have access to on your account, and allows you to specify which collections you want to be included in your binary analysis by clicking on the checkbox. Selecting no collections will enable all the available collections in your search.

Move the slider to determine the confidence level you want to use for batch renaming. Any function returned that is higher than this value will automatically be renamed in the listing view. Clicking the `Fetch Results` button will kick-off the analysis, which you can track in the progress bar.

![auto_analyze_dialog](./assets/img/8.png)

Once the analysis is complete, the results panel is enabled. This provides information on what symbols can be renamed, and to what, along with a message explaining why the change occurred.

![auto_analyze_results](./assets/img/9.png)

## Generate Block Summaries

Right-clicking on any function name in an IDA View and selecting `Generate AI Summaries` will bring up the following window which allows you to generate block summaries.

![generate_summaries](./assets/img/14.png)

Once clicked, a dialog box appears inviting to confirm the generation of block summaries.

![confirm_summaries](./assets/img/15.png)

⚠️ This action is irrevocable and no refunds can be issued on the credits used.

# Troubleshooting

- Only IDA v8.0 or later is supported with Python 3.9 and higher.

# Software Requirements

RevEng.AI IDA uses:
- [reait](https://github.com/RevEngAI/reait)
