import customtkinter as ctk
from scapy.all import *
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import psutil
from tkinter import filedialog

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.dot11 import Dot11
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import STP, Dot3, ARP, Ether
from scapy.contrib.lldp import LLDPDU

from scapy.utils import rdpcap


class PacketCaptureApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Packet Capture App")
        self.geometry("1920x1080")

        self.frames = {}
        self.filter_text = ""
        self.packet_data = []
        self.src_ip_count = {}
        self.dst_ip_count = {}

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.frames["interface_selection"] = self.create_interface_selection_frame()

        self.show_frame("interface_selection")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

    def create_pos_selection(self):
        # criar apenas a primera vez
        if "packet_table" not in self.frames or not self.frames["packet_table"]:
            self.frames["packet_table"] = self.create_packet_table_frame()
            self.frames["protocol_graph"] = self.create_protocol_graph_frame()

    def show_frame(self, frame_name):
        frame = self.frames[frame_name]
        frame.pack(fill="both", expand=True)

        for name, widget in self.frames.items():
            if name != frame_name:
                widget.pack_forget()

    def create_interface_selection_frame(self):
        frame = ctk.CTkFrame(self)

        appTitle = ctk.CTkLabel(self, text="Packet Capture App")
        appTitle.pack(padx=20, pady=20)

        interfaces = list(psutil.net_if_addrs().keys())
        self.interface_var = ctk.StringVar(value=interfaces[0])

        content_frame = ctk.CTkFrame(frame)
        content_frame.pack(expand=True)

        interface_menu = ctk.CTkOptionMenu(
            content_frame, variable=self.interface_var, values=interfaces, command=self.interface_changed
        )
        interface_menu.pack(pady=20)

        start_button = ctk.CTkButton(
            content_frame, text="Start Capture", command=self.start_capture
        )
        start_button.pack(pady=20)

        import_button = ctk.CTkButton(
            content_frame, text="Import Capture", command=self.import_capture
        )
        import_button.pack(pady=20)

        frame.pack(fill="both", expand=True)
        return frame

    def create_packet_table_frame(self):
        frame = ctk.CTkFrame(self)

        self.table_headers = ["No.", "Source IP", "Destination IP", "Protocol", "Length", "Info"]
        self.packet_table = ctk.CTkScrollableFrame(frame, width=800)
        self.packet_table.pack(pady=10, padx=10, fill="both", expand=True)

        self.create_table_headers()
        self.rownum = 0

        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=10)

        self.back_button = ctk.CTkButton(
            button_frame, text="New Capture", command=self.return_to_interface_selection
        )
        self.back_button.pack(side="left", padx=5)

        self.filter_frame = ctk.CTkFrame(frame)
        self.filter_frame.pack(pady=10, padx=10)

        self.filter_entry = ctk.CTkEntry(self.filter_frame, placeholder_text="Enter filter (e.g., TCP, 192.168.0.1)")
        self.filter_entry.pack(side="left", padx=5)

        self.filter_button = ctk.CTkButton(
            self.filter_frame, text="Apply Filter", command=self.apply_filter
        )
        self.filter_button.pack(side="left", padx=5)

        self.clear_filter_button = ctk.CTkButton(
            self.filter_frame, text="Clear Filter", command=self.clear_filter
        )
        self.clear_filter_button.pack(side="left", padx=5)

        self.button_frame = ctk.CTkFrame(frame)
        self.button_frame.pack(pady=10, padx=10)

        self.stop_button = ctk.CTkButton(
            self.button_frame, text="Stop Capture", command=self.stop_capture
        )
        self.stop_button.pack(side="left", padx=5)

        self.export_button = ctk.CTkButton(
            self.button_frame, text="Export to PCAP", command=self.export_to_pcap
        )
        self.export_button.pack(side="left", padx=5)

        self.graph_button = ctk.CTkButton(
            self.button_frame, text="Graphs", command=lambda: self.show_frame("protocol_graph")
        )
        self.graph_button.pack(side="left", padx=5)

        return frame

    def create_protocol_graph_frame(self):
        frame = ctk.CTkFrame(self)

        frame.grid_rowconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        self.protocol_count = {}
        self.protocol_fig, self.protocol_ax = plt.subplots(figsize=(6, 4))
        self.protocol_ax.set_title("Protocol Distribution", color='white')
        self.protocol_fig.patch.set_facecolor('gray')
        self.protocol_ax.set_facecolor('gray')

        self.src_ip_fig, self.src_ip_ax = plt.subplots(figsize=(6, 4))
        self.dst_ip_fig, self.dst_ip_ax = plt.subplots(figsize=(6, 4))

        self.src_ip_canvas = FigureCanvasTkAgg(self.src_ip_fig, master=frame)
        self.src_ip_canvas.get_tk_widget().grid(row=1, column=0, padx=10, pady=10)

        self.dst_ip_canvas = FigureCanvasTkAgg(self.dst_ip_fig, master=frame)
        self.dst_ip_canvas.get_tk_widget().grid(row=1, column=1, padx=10, pady=10)

        self.canvas = FigureCanvasTkAgg(self.protocol_fig, master=frame)
        self.canvas.get_tk_widget().grid(row=2, column=0, columnspan=2, pady=20)

        back_button = ctk.CTkButton(
            frame, text="Back", command=lambda: self.show_frame("packet_table")
        )
        back_button.grid(row=3, column=0, columnspan=2, pady=10)

        frame.bind("<Destroy>", lambda event: plt.close(self.protocol_fig))
        frame.bind("<Destroy>", lambda event: plt.close(self.src_ip_fig))
        frame.bind("<Destroy>", lambda event: plt.close(self.dst_ip_fig))

        return frame

    def create_table_headers(self):
        for col, header in enumerate(self.table_headers):
            label = ctk.CTkLabel(
                self.packet_table,
                text=header,
                width=150,
                anchor="w",
                font=("Arial", 12, "bold")
            )
            label.grid(row=0, column=col, sticky="w", padx=5, pady=5)

    def add_packet_to_table(self, packet_data):
        row_idx = self.rownum
        for col, data in enumerate(packet_data):
            label = ctk.CTkLabel(
                self.packet_table,
                text=data,
                anchor="w",
                font=("Arial", 10)
            )
            label.grid(row=row_idx + 1, column=col, sticky="w", padx=5, pady=5)
            label.bind("<Double-Button-1>", lambda event, idx=row_idx: self.show_packet_details(idx))

    def apply_filter(self):
        self.filter_text = self.filter_entry.get().strip().lower()
        self.update_table()

    def clear_filter(self):
        self.filter_text = ""
        self.filter_entry.delete(0, "end")
        self.update_table()

    def update_table(self):
        self.clear_table()

        if self.filter_text == "":
            for packet_data in self.packet_data:
                self.rownum += 1
                self.add_packet_to_table(packet_data[:-1])
        else:
            for packet_data in self.packet_data:
                if self.filter_matches(packet_data):
                    self.rownum += 1
                    self.add_packet_to_table(packet_data[:-1])

    def filter_matches(self, packet_info):
        source_ip = packet_info[1].lower()
        destination_ip = packet_info[2].lower()
        protocol = packet_info[3].lower()

        return (
                self.filter_text in source_ip
                or self.filter_text in destination_ip
                or self.filter_text in protocol
        )

    def show_packet_details(self, packet_index):
        packet_info = self.packet_data[packet_index]
        packet = packet_info[-1]

        details_window = ctk.CTkToplevel(self)
        details_window.title("Packet Details")
        details_window.geometry("600x400")

        headers_frame = ctk.CTkFrame(details_window)
        headers_frame.pack(pady=10, fill="both", expand=True)

        headers_label = ctk.CTkLabel(headers_frame, text="Packet Headers:", font=("Arial", 12, "bold"))
        headers_label.pack(anchor="w", padx=10, pady=5)

        headers_text = ctk.CTkTextbox(headers_frame, width=560, height=150, font=("Courier", 10))
        headers_text.pack(pady=5, padx=10, fill="both", expand=True)
        headers_text.insert("1.0", packet.show(dump=True))

        hex_frame = ctk.CTkFrame(details_window)
        hex_frame.pack(pady=10, fill="both", expand=True)

        hex_label = ctk.CTkLabel(hex_frame, text="Hexadecimal Data:", font=("Arial", 12, "bold"))
        hex_label.pack(anchor="w", padx=10, pady=5)

        hex_text = ctk.CTkTextbox(hex_frame, width=560, height=150, font=("Courier", 10))
        hex_text.pack(pady=5, padx=10, fill="both", expand=True)

        hex_view = self.format_hex(packet)
        hex_text.insert("1.0", hex_view)

        close_button = ctk.CTkButton(details_window, text="Close", command=details_window.destroy)
        close_button.pack(pady=10)

    def format_hex(self, packet):
        raw_bytes = bytes(packet)
        hex_lines = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i + 16]
            hex_chunk = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_chunk = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            hex_lines.append(f"{i:04x}  {hex_chunk:<48}  {ascii_chunk}")
        return "\n".join(hex_lines)

    def process_packet(self, packet):
        protocol = "Unknown"
        src_ip = dst_ip = "N/A"
        info = "N/A"
        length = len(packet)

        ipv4_protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }

        ipv6_protocols = {
            6: "TCP",
            17: "UDP",
        }

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto_number = packet[IP].proto
            protocol = ipv4_protocols.get(proto_number, f"IPv4-{proto_number}")

        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            proto_number = packet[IPv6].nh
            protocol = ipv6_protocols.get(proto_number, f"IPv6-{proto_number}")

        elif ARP in packet:
            src_ip = packet[ARP].hwsrc
            dst_ip = packet[ARP].hwdst
            protocol = "ARP"

        elif Ether in packet:
            src_ip = packet[Ether].src
            dst_ip = packet[Ether].dst
            protocol = "Ethernet"

        if TCP in packet and packet[TCP].payload:
            payload = bytes(packet[TCP].payload)

            if payload.startswith(b"GET") or payload.startswith(b"POST") or b"HTTP" in payload:
                protocol = "HTTP"
                info = "HTTP Request/Response"

            elif payload.startswith(b"\x16"):
                protocol = "TLS"
                info = "TLS Handshake"
            else:
                info = "Application Data"

        elif UDP in packet and packet[UDP].payload:

            if DNS in packet:
                protocol = "DNS"
                if packet[DNS].qr == 0:
                    info = "DNS Query"
                else:
                    info = "DNS Response"
            else:
                info = "UDP Payload"

        elif ICMP in packet:
            protocol = "ICMP"
            info = f"Type {packet[ICMP].type}, Code {packet[ICMP].code}"

        elif STP in packet:
            protocol = "STP"
            info = "Spanning Tree Protocol"

        elif LLDPDU in packet:
            protocol = "LLDP"
            info = "Link Layer Discovery Protocol"

        self.src_ip_count[src_ip] = self.src_ip_count.get(src_ip, 0) + 1
        self.dst_ip_count[dst_ip] = self.dst_ip_count.get(dst_ip, 0) + 1

        self.rownum += 1
        packet_info = [len(self.packet_data) + 1, src_ip, dst_ip, protocol, length, info, packet]
        self.packet_data.append(packet_info)

        if self.filter_text == "" or self.filter_matches(packet_info):
            self.after(0, self.add_packet_to_table, packet_info[:-1])

        self.after(0, self.update_protocol_graph)
        self.after(0, self.update_ip_graphs)
        self.update_protocol_data(protocol)

    def start_capture(self):
        self.create_pos_selection()
        self.interface = self.interface_var.get()
        self.clear_graphs()

        self.show_frame("packet_table")
        self.capturing = True
        self.sniff_packets()

    def sniff_packets(self):
        def capture():
            while self.capturing:
                sniff(iface=self.interface, prn=self.process_packet, count=1, store=False)

        threading.Thread(target=capture, daemon=True).start()

    def export_to_pcap(self):
        file_path = filedialog.asksaveasfilename(
            title="Save as PCAP",
            defaultextension=".pcap",
            filetypes=(("PCAP files", "*.pcap"), ("All files", "*.*"))
        )

        if not file_path:
            print("Export canceled by user.")
            return

        try:

            packets = [packet_info[-1] for packet_info in self.packet_data]
            wrpcap(file_path, packets)
            print(f"Successfully exported {len(packets)} packets to {file_path}.")
        except Exception as e:
            print(f"Failed to export packets: {e}")

    def stop_capture(self):
        self.capturing = False
        self.close_graphs()

    def sort_table(self, col):
        col_name = self.table_headers[col]
        if col_name == "No.":
            key = lambda x: x[0]
        elif col_name == "Source IP":
            key = lambda x: x[1]
        elif col_name == "Destination IP":
            key = lambda x: x[2]
        else:
            key = lambda x: x[3]

        self.packet_data.sort(key=key, reverse=True)

        self.clear_table()
        for packet_info in self.packet_data:
            self.add_packet_to_table(packet_info)

    def clear_table(self):
        for widget in self.packet_table.winfo_children():
            widget.destroy()
        self.rownum = 0
        self.create_table_headers()

    def update_protocol_graph(self):
        self.protocol_ax.clear()
        self.protocol_ax.set_facecolor('gray')
        labels = list(self.protocol_count.keys())
        sizes = list(self.protocol_count.values())
        self.protocol_ax.set_title("Protocol Percentage", color='white')

        self.protocol_ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        self.protocol_ax.legend(labels, loc="upper right", bbox_to_anchor=(1.05, 1))
        self.protocol_ax.axis('equal')
        self.canvas.draw()

    def update_ip_graphs(self):
        top_src_ips = sorted(self.src_ip_count.items(), key=lambda x: x[1], reverse=True)[:3]
        top_dst_ips = sorted(self.dst_ip_count.items(), key=lambda x: x[1], reverse=True)[:3]

        self.src_ip_ax.clear()
        self.dst_ip_ax.clear()

        src_ips, src_counts = zip(*top_src_ips)
        self.src_ip_ax.set_title("Top 3 Source IPs", color='white')
        self.src_ip_ax.bar(src_ips, src_counts, color='skyblue')

        self.src_ip_ax.set_facecolor('gray')
        self.src_ip_ax.tick_params(axis='x', labelsize=6)

        dst_ips, dst_counts = zip(*top_dst_ips)
        self.dst_ip_ax.bar(dst_ips, dst_counts, color='lightcoral')
        self.dst_ip_ax.set_title("Top 3 Destination IPs", color='white')
        self.dst_ip_ax.set_facecolor('gray')
        self.dst_ip_ax.tick_params(axis='x', labelsize=6)

        self.src_ip_canvas.draw()
        self.dst_ip_canvas.draw()

    def update_protocol_data(self, protocol):
        if protocol in self.protocol_count:
            self.protocol_count[protocol] += 1
        else:
            self.protocol_count[protocol] = 1

    def interface_changed(self, value):
        print(f"Interface changed to: {value}")

    def import_capture(self):
        self.create_pos_selection()
        self.capturing = False
        self.show_frame("packet_table")
        self.import_packets()

    def import_packets(self):
        file_path = filedialog.askopenfilename(
            title="Select a PCAP file",
            filetypes=(("PCAP files", "*.pcap"), ("All files", "*.*"))
        )

        if not file_path:
            print("File Not Found")
            return

        try:

            packets = rdpcap(file_path)
            self.clear_table()
            self.clear_graphs()

            def process():
                for packet in packets:
                    self.process_packet(packet)

            threading.Thread(target=process, daemon=True).start()

            print(f"Successfully imported {len(packets)} packets from {file_path}.")
        except Exception as e:
            print(f"Failed to import PCAP file: {e}")
        self.close_graphs()

    def on_close(self):
        if "packet_table" in self.frames:
            if self.capturing:
                self.stop_capture()
        self.destroy()

    def close_graphs(self):
        plt.close(self.protocol_fig)
        plt.close(self.dst_ip_fig)
        plt.close(self.src_ip_fig)

    def clear_graphs(self):
        self.protocol_count = {}
        self.src_ip_count = {}
        self.dst_ip_count = {}
        self.update_protocol_graph()
        #self.update_ip_graphs()

    def return_to_interface_selection(self):
        self.stop_capture()
        self.packet_data.clear()
        self.rownum = 0

        for widget in self.packet_table.winfo_children():
            widget.destroy()
        self.create_table_headers()

        self.show_frame("interface_selection")


if __name__ == "__main__":
    app = PacketCaptureApp()
    app.mainloop()
