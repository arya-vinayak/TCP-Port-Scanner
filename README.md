# TCP Port Scanner

This is a simple Streamlit app that performs TCP port scanning on a given host.

## Installation

1. Clone this repository to your local machine.
2. Install the required dependencies by running `pip install -r requirements.txt`.
3. Run the app with `streamlit run app.py`.

## Usage

1. Enter the host IP or hostname that you want to scan in the input box.
2. Select the scanning mode that you want to use: "Single Port" or "Range of Ports".
3. If you selected "Single Port", enter the port number that you want to scan in the input box provided. If you selected "Range of Ports", enter the start and end ports in the input boxes provided.
4. Click on the "Scan Ports" button to start the port scanning process.
5. The results of the scan will be displayed in the table below.
6. If you want to compare scan results, enter the host IP or hostname and the port number or range of ports that you want to scan in the input boxes provided under the "Compare Results" section.
7. Click on the "Compare Results" button to start the comparison process.
8. The comparison results will be displayed in the table below.
9. If you want to plot the results of the scan, click on the "Plot Results" button.
10. The plot will be displayed below the table.

Note: This app is intended for educational purposes only. Do not use it to scan hosts without proper authorization.

## Credits

This app was created by Arya Vinayak R as a project for the Computer Networks Course at PES University.

