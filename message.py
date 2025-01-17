import customtkinter as ctk
from scapy.all import sniff, PcapWriter, IP, TCP, UDP, ICMP, rdpcap
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import psutil
from tkinter import filedialog


class PacketCaptureApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Packet Capture App")
        self.geometry("1920x1080")

        self.frames = {}

        self.frames["interface_selection"] = self.create_interface_selection_frame()

        self.frames["packet_table"] = self.create_packet_table_frame()

        self.frames["protocol_graph"] = self.create_protocol_graph_frame()

        self.show_frame("interface_selection")

    def show_frame(self, frame_name):
        frame = self.frames[frame_name]
        frame.pack(fill="both", expand=True)

        for name, widget in self.frames.items():
            if name != frame_name:
                widget.pack_forget()

    def create_interface_selection_frame(self):
        frame = ctk.CTkFrame(self)

        interfaces = list(psutil.net_if_addrs().keys())

        self.interface_var = ctk.StringVar(value=interfaces[0])

        # Sub-frame para centralizar conteúdo
        content_frame = ctk.CTkFrame(frame)
        content_frame.pack(expand=True)  # Expande para centralizar no frame principal

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

        frame.pack(fill="both", expand=True)  # Expande o frame principal para ocupar toda a janela
        return frame

    def create_packet_table_frame(self):
        frame = ctk.CTkFrame(self)

        self.table_headers = ["No.", "Source IP", "Destination IP", "Protocol"]
        self.packet_table = ctk.CTkScrollableFrame(frame, width=800)
        self.packet_table.pack(pady=10, padx=10, fill="both", expand=True)

        self.create_table_headers()

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

        self.protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "IP": 0, "Unknown": 0}

        self.protocol_fig, self.protocol_ax = plt.subplots(figsize=(6, 4))
        self.protocol_ax.set_title("Protocol Distribution")

        self.graph_frame = ctk.CTkFrame(frame)
        self.graph_frame.pack(pady=10)
        self.canvas = FigureCanvasTkAgg(self.protocol_fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack()

        back_button = ctk.CTkButton(
            frame, text="Back", command=lambda: self.show_frame("packet_table")
        )
        back_button.pack(pady=10)

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
            label.bind("<Button-1>", lambda event, col=col: self.sort_table(col))

    def add_packet_to_table(self, packet_info):
        row_idx = len(self.packet_data)  # Ensure proper row index
        for col, data in enumerate(packet_info):
            label = ctk.CTkLabel(
                self.packet_table,
                text=data,
                anchor="w",
                font=("Arial", 10)
            )
            label.grid(row=row_idx + 1, column=col, sticky="w", padx=5, pady=5)
            label.bind("<Double-Button-1>", lambda event, idx=row_idx: self.show_packet_details(idx))

    def start_capture(self):
        self.interface = self.interface_var.get()
        self.packet_data = []
        self.protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "IP": 0, "Unknown": 0}

        self.show_frame("packet_table")

        self.capturing = True
        self.sniff_packets()

    def show_packet_details(self, packet_index):
        packet_info = self.packet_data[packet_index]
        packet = packet_info[-1]  # Obtém o pacote Scapy

        details_window = ctk.CTkToplevel(self)
        details_window.title("Packet Details")
        details_window.geometry("600x400")

        # Cabeçalhos do pacote
        headers_frame = ctk.CTkFrame(details_window)
        headers_frame.pack(pady=10, fill="both", expand=True)

        headers_label = ctk.CTkLabel(headers_frame, text="Packet Headers:", font=("Arial", 12, "bold"))
        headers_label.pack(anchor="w", padx=10, pady=5)

        headers_text = ctk.CTkTextbox(headers_frame, width=560, height=150, font=("Courier", 10))
        headers_text.pack(pady=5, padx=10, fill="both", expand=True)
        headers_text.insert("1.0", packet.show(dump=True))  # Exibe os cabeçalhos

        # Dados em formato hexadecimal
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

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            else:
                protocol = "IP"

        packet_info = [len(self.packet_data) + 1, src_ip, dst_ip, protocol, packet]
        self.packet_data.append(packet_info)

        self.after(0, self.add_packet_to_table, packet_info[:-1])

        self.protocol_count[protocol] += 1
        self.update_protocol_graph()

    def sniff_packets(self):
        def capture():
            self.writer = PcapWriter("captured_packets.pcap", append=True, sync=True)
            while self.capturing:
                sniff(iface=self.interface, prn=self.process_packet, count=1, store=False)
                time.sleep(0.5)
            self.writer.close()

        threading.Thread(target=capture, daemon=True).start()

    def export_to_pcap(self):
        print("Exporting packets to PCAP file...")
        print("Pacotes exportados para captured_packets.pcap")

    def stop_capture(self):
        self.capturing = False

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
            if isinstance(widget, ctk.CTkLabel) and widget.grid_info()['row'] != '0':
                widget.destroy()

    def update_protocol_graph(self):
        self.protocol_ax.clear()

        labels = list(self.protocol_count.keys())
        sizes = list(self.protocol_count.values())

        self.protocol_ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        self.protocol_ax.axis('equal')

        self.canvas.draw()

    def interface_changed(self, value):
        print(f"Interface changed to: {value}")

    def import_capture(self):
        self.show_frame("packet_table")
        self.import_packets()

    def import_packets(self):
        # Open a file dialog to select a PCAP file
        file_path = filedialog.askopenfilename(
            title="Select a PCAP file",
            filetypes=(("PCAP files", "*.pcap"), ("All files", "*.*"))
        )

        if not file_path:
            print("File Not Found")
            return

        try:
            # Load packets from the PCAP file
            packets = rdpcap(file_path)
            self.clear_table()
            self.packet_data = []  # Reset the packet data list
            self.protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "IP": 0, "Unknown": 0}

            # Process each packet
            for packet in packets:
                self.process_packet(packet)

            def process():
                for packet in packets:
                    self.process_packet(packet)

            threading.Thread(target=process, daemon=True).start()

            print(f"Successfully imported {len(packets)} packets from {file_path}.")
        except Exception as e:
            print(f"Failed to import PCAP file: {e}")

    def clear_table(self):
        for widget in self.packet_table.winfo_children():
            if isinstance(widget, ctk.CTkLabel) and widget.grid_info()['row'] != 0:
                widget.destroy()


if __name__ == "__main__":
    app = PacketCaptureApp()
    app.mainloop()
