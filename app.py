import streamlit as st
from scapy.all import *
import socket
import time
import plost
import matplotlib.pyplot as plt
from pyecharts import options as opts
from pyecharts.charts import Bar
from streamlit_echarts import st_pyecharts

 


st.title("TCP Port Scanner")

methods = {
    "SYN": "SYN scan",
    "UDP": "UDP scan",
    "TCP": "TCP connect scan",
}


def scan(host, port, method):
    if method == "SYN":
        return syn_scan(host, port)
    elif method == "UDP":
        return udp_scan(host, port)
    elif method == "TCP":
        return tcp_scan(host, port)
    else :
        return "Invalid method"
    


# Define scan methods
def check_host(host):
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


def syn_scan(host, port):
    # SYN scan
    start = time.time()
    if check_host(host):
        packet = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=2, verbose=1)
        if response is None:
            return "Filtered", time.time() - start
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                send_rst = sr(
                    IP(dst=host) / TCP(dport=port, flags="AR"), timeout=2, verbose=0
                )

                return "Open", time.time() - start
            elif response.getlayer(TCP).flags == 0x14:
                return "Closed", time.time() - start
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type) == 3 and int(
                response.getlayer(ICMP).code
            ) in [1, 2, 3, 9, 10, 13]:
                return "Filtered", time.time() - start
    else:
        return "Invalid host", time.time() - start


def udp_scan(host, port):
    # UDP scan
    start = time.time()
    if check_host(host):
        packet = IP(dst=host) / UDP(dport=port)
        response = sr1(packet, timeout=2, verbose=0)
        if response is None:
            return "Open|Filtered", time.time() - start
        elif response.haslayer(UDP):
            return "Open", time.time() - start
        elif response.haslayer(ICMP):
            if (
                int(response.getlayer(ICMP).type) == 3 # ICMP type 3 = Destination Unreachable
                and int(response.getlayer(ICMP).code) == 3 # ICMP code 3 = Port unreachable
            ):
                return "Closed", time.time() - start
            elif int(response.getlayer(ICMP).type) == 3 and int(
                response.getlayer(ICMP).code
            ) in [1, 2, 9, 10, 13]: # ICMP code 1, 2, 9, 10, 13 = Host unreachable, Protocol unreachable, Destination network unreachable, Destination host unreachable, Communication administratively prohibited
                return "Filtered", time.time() - start
    else:
        return "Invalid host", time.time() - start


def tcp_scan(host, port):
    # TCP scan
    start = time.time()
    if check_host(host):
        packet = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=2, verbose=0)
        if response is None:
            return "Filtered", time.time() - start
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # TCP flags 0x12 = SYN, ACK
                send_rst = sr(
                    IP(dst=host) / TCP(dport=port, flags="AR"), timeout=2, verbose=0
                )
                return "Open", time.time() - start
            elif response.getlayer(TCP).flags == 0x14:
                return "Closed", time.time() - start  # TCP flags 0x14 = RST, ACK
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type) == 3 and int(
                response.getlayer(ICMP).code
            ) in [
                1,
                2,
                3,
                9,
                10,
                13,
            ]:  # ICMP type 3 = Destination Unreachable
                return "Filtered", time.time() - start
    else:
        return "Invalid host", time.time() - start

def compare_scan(host, port, method1, method2):
    # Compare two scan methods
    result1, time_taken1 = scan(host, port, method1)
    result2, time_taken2 = scan(host, port, method2)
    # Present comparison
    st.write("Scan method 1: %s" % method1)
    st.write("Scan method 2: %s" % method2)
    st.write("Scan method 1 result: %s" % result1)
    st.write("Scan method 2 result: %s" % result2)
    st.write("Scan method 1 time taken: %f" % time_taken1)
    st.write("Scan method 2 time taken: %f" % time_taken2)
    if result1 == result2:
        st.write("Results are the same")
    else:
        st.write("Results are different")



def scan_range(host, port_range, method="SYN"):
    # Scan a range of ports
    results = []
    for port in port_range:
        result, time_taken = scan(host, port, method)
        results.append([port, result, time_taken])
    return results

# Define the list_types function
def list_types():
    # List all scan methods
    for method in methods:
        st.write(f"{method}: {methods[method]}")
    return


import streamlit as st

import pandas as pd

def plot_results(results):
    # Plot results of the scan in a graph
    ports = []
    status = []
    time_taken = []
    for result in results:
        ports.append(result[0])
        status.append(result[1])
        time_taken.append(result[2])
    # stats = {
    #     "Open": status.count("Open"),
    #     "Closed": status.count("Closed"),
    #     "Filtered": status.count("Filtered"),
    #     "Invalid host": status.count("Invalid host"),
    # }
    # stats_df = pd.DataFrame(stats, index=[0])
    # st.bar_chart(stats_df)
    # labels = 'Open', 'Closed', 'Filtered', 'Invalid host'
    # sizes = [status.count('Open'),status.count('Closed'),status.count('Filtered'),status.count('Invalid host')]
    # #explode = (0, 0.1, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

    # fig1, ax1 = plt.subplots()
    # ax1.pie(sizes, labels=labels, autopct='%1.1f%%',
    #         shadow=True, startangle=90)
    # ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    # st.pyplot(fig1)
    b = (
    Bar()
    .add_xaxis(["Open", "Closed", "Filtered", "Invalid host"])
    .add_yaxis(
        "Count", [status.count("Open"),status.count("Closed"),status.count("Filtered"),status.count("Invalid host")]
    )
    .set_global_opts(
        title_opts=opts.TitleOpts(
            title="Scanned Range ", 
        ),
        toolbox_opts=opts.ToolboxOpts(),
    )
    )
    st_pyecharts(b)




def print_results(results):
    # Print results
    for result in results:
        # Check content and print colour accordingly
        if result[1] == "Open":
            st.write(f"<span style='color:green'>{result[0]} {result[1]} {result[2]}</span>", unsafe_allow_html=True)
        elif result[1] == "Closed":
            st.write(f"<span style='color:red'>{result[0]} {result[1]} {result[2]}</span>", unsafe_allow_html=True)
        elif result[1] == "Filtered":
            st.write(f"<span style='color:orange'>{result[0]} {result[1]} {result[2]}</span>", unsafe_allow_html=True)
        else:
            st.write(f"{result[0]} {result[1]} {result[2]}")

import streamlit as st

def menu():
    # Menu
    st.sidebar.header("Select an option")
    options = ["Scan a single port", "Scan a range of ports", "List types of scans",
               "Compare two scan methods", "Plot results", "Export results"]
    choice = st.sidebar.selectbox("", options)

    if choice == "Scan a single port":
        st.header("Scan a single port")
        host = st.text_input("Enter host:")
        port = st.number_input("Enter port:", value=0, step=1, format="%d")
        method = st.text_input("Enter scan method:")
        if st.button("Scan"):
            result, time_taken = scan(host, port, method)
            if result == "Open":
                st.success(f"{result} {time_taken}")
            elif result == "Closed":
                st.error(f"{result} {time_taken}")
            elif result == "Filtered":
                st.warning(f"{result} {time_taken}")
            else:
                st.write(f"{result} {time_taken}")
            st.write(f"Time taken: {time_taken}")

    elif choice == "Scan a range of ports":
        st.header("Scan a range of ports")
        host = st.text_input("Enter host:")
        port_range = st.text_input("Enter port range (e.g., '1-100'):")
        method = st.text_input("Enter scan method:")
        if st.button("Scan"):
            port_range = port_range.split("-")
            port_range = range(int(port_range[0]), int(port_range[1]) + 1)
            results = scan_range(host, port_range, method)
            st.table(results)

    elif choice == "List types of scans":
        st.header("List types of scans")
        list_types()

    elif choice == "Compare two scan methods":
        st.header("Compare two scan methods")
        host = st.text_input("Enter host:")
        port = st.number_input("Enter port:", value=0, step=1, format="%d")
        method1 = st.text_input("Enter scan method 1:")
        method2 = st.text_input("Enter scan method 2:")
        if st.button("Compare"):
            compare_scan(host, port, method1, method2)

    elif choice == "Plot results":
        st.header("Plot results")
        host = st.text_input("Enter host:")
        port_range = st.text_input("Enter port range (e.g., '1-100'):")
        method = st.text_input("Enter scan method:")
        if st.button("Scan and plot"):
            port_range = port_range.split("-")
            port_range = range(int(port_range[0]), int(port_range[1]) + 1)
            results = scan_range(host, port_range, method)
            plot_results(results)

    # elif choice == "Export results":
    #     st.header("Export results")
    #     host = st.text_input("Enter host:")
    #     port_range = st.text_input("Enter port range (e.g., '1-100'):")
    #     method = st.text_input("Enter scan method:")
    #     if st.button("Export"):
    #         port_range = port_range.split("-")
    #         port_range = range(int(port_range[0]), int(port_range[1]) + 1)
    #         results = scan_range(host, port_range, method)
    #         export_results(results)

if __name__ == "__main__":
    menu()





    



