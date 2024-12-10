# Mac Recovery Image Downloader (Unofficial)

As the name may suggest, this is a version of opencorePKG's Macrecovery program, but with a GUI so make things easier.


## Disclaimer

This script interacts with Apple's servers in a way not officially supported.  Apple may change their systems at any time, rendering this script non-functional.  I am not responsible for any consequences arising from the use of this script.  Use it at your own risk.


## Features

*   **GUI-based:** User-friendly graphical interface built with Tkinter.
*   **Board ID Selection:** Choose from a list of supported Apple board IDs.
*   **macOS Version Display:**  The macOS version associated with each board ID is displayed in the dropdown.
*   **Optional MLB Serial:** Enter your MLB (Logic Board Serial Number) for potentially more specific results.  If left blank, a default value is used.
*   **OS Type Selection:** Choose between "default" (older) and "latest" recovery images.
*   **Diagnostics Image Option:**  Download a diagnostics image instead of a standard recovery image.
*   **Output Directory Selection:** Choose the folder where the downloaded files will be saved.
*   **Download Progress:**  A log displays download progress.
*   **File Naming:** Output files are consistently named "Basesystem.dmg" and "Basesystem.chunklist."


## Requirements

*   Python 3.x (tested with 3.10 and above)
*   Required Python Packages (install using `pip install -r requirements.txt`):
    *   `tkinter` (usually included with Python)
    *   `requests`
    *   `hashlib`
    *   `json`
    *   `struct`
    *   `string`
    *   `os`
    *   `random`
    *   `sys`
    *   `threading`
    *   `time`

## Usage

1.  **Install Dependencies:** Create a `requirements.txt` file with the list above and then run `pip install -r requirements.txt`
2.  **Run the Script:** Execute the Python script (`macrecoveryGUI.py`).
3.  **Select Options:** Choose the desired Board ID, optionally enter your MLB serial number, select the OS type, and check the "Diagnostics Image" box if needed. Choose the output directory using the "Browse" button.
4.  **Download:** Click the "Download" button.  The download progress will be shown in the log.

## Notes

*   The list of supported Board IDs is limited and may not be comprehensive.
*   Apple's server responses are used and could change at any time.
*   Successful verification of downloaded images depends on the validity of the downloaded `chunklist`.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
