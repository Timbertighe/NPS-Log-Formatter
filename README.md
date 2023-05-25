# IAS-Log-Formatter
## Overview
    Windows IAS (NPS) logs are chronically hard to read.
    This script will parse through these files, and output a single logfile with human readable information
    For dot1x events, Access-Request events are correlated with Access-Reject and Access-Accept events
    When there is a rejection, the error code is converted to a human-readable error description

## Prerequisites
    Install python 3.10 or later
    Install the xmltodict package
        pip install xmltodict

## Running the Script
    Run the script from the same location as the IAS log files
    This means you need to run the script on the NPS server, or copy the files to another location
    On the NPS server, the log files are stored in C:\Windows\System32\LogFiles

## Reading the Output
    The output will be a json file, including today's date
    The best way to interpret this is in Notepad++:
        https://notepad-plus-plus.org/downloads/
    Then, use the NPPJSONViewer plugin to format it nicely
        https://github.com/kapilratnani/JSON-Viewer
    Alternatively, use an online JSON formatter, such as:
        https://jsonviewer.stack.hu/

## Testing Notes
    This has been tested in an environment that uses RADIUS for:
    - 802.1X Ethernet
    - 802.1X WiFi
    - SSH logons from network devices
    
    It is possible that results will vary in other environments
