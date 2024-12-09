import customtkinter as ctk
from scapy.all import sniff, IP, TCP, UDP, ICMP


# Interface
class PacketCaptureApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Packet Capture Table")
        self.geometry("800x400")

        # Create Table Headers
        self.table_headers = ["No.", "Source IP", "Destination IP", "Protocol"]
        self.packet_table = ctk.CTkScrollableFrame(self, width=800)
        self.packet_table.pack(pady=10, padx=10, fill="both", expand=True)

        self.create_table_headers()
        self.packet_data = []  # Store captured packets

        # State for capturing packets
        self.capturing = False

        # Buttons
        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.pack(pady=10, padx=10)
        self.start_button = ctk.CTkButton(
            self.button_frame, text="Start Capture", command=self.button_call_start, fg_color="Red"
        )
        self.start_button.pack(side="left", padx=5)
        self.stop_button = ctk.CTkButton(
            self.button_frame, text="Stop Capture", command=self.button_call_stop
        )
        self.stop_button.pack(side="left", padx=5)

    def create_table_headers(self):
        # Create header labels for the table
        for col, header in enumerate(self.table_headers):
            label = ctk.CTkLabel(
                self.packet_table,
                text=header,
                width=150,
                anchor="w",
                font=("Arial", 12, "bold")
            )
            label.grid(row=0, column=col, sticky="w", padx=5, pady=5)

    def add_packet_to_table(self, packet_info):
        # Add a new row to the table
        row_idx = len(self.packet_data)  # New row number
        for col, data in enumerate(packet_info):
            label = ctk.CTkLabel(
                self.packet_table,
                text=data,
                anchor="w",
                font=("Arial", 10)
            )
            label.grid(row=row_idx, column=col, sticky="w", padx=5, pady=5)

    def process_packet(self, packet):
        # Extract packet information
        protocol = "Unknown"
        src_ip = dst_ip = "N/A"
        # print(packet[2])

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

        # Add the packet data to the table
        packet_info = [len(self.packet_data) + 1, src_ip, dst_ip, protocol]
        self.packet_data.append([len(self.packet_data) + 1, packet])
        self.add_packet_to_table(packet_info)

    def sniff_packets(self):
        # Start packet capture in the background
        def capture():
            while self.capturing:  # Continue sniffing until stopped
                sniff(prn=self.process_packet, count=1, store=False)

        import threading
        threading.Thread(target=capture, daemon=True).start()

    # Test Button
    def button_callback(self):
        print("button clicked")
        print(self.packet_data)

    # Start sniff
    def button_call_start(self):
        print("Start")
        if not self.capturing:
            self.capturing = True
            self.sniff_packets()
            self.start_button.configure(fg_color="Green")

    # Stop sniff
    def button_call_stop(self):
        print("Stop")
        self.capturing = False
        self.start_button.configure(fg_color="Red")


# Run the Application
if __name__ == "__main__":
    app = PacketCaptureApp()
    app.mainloop()
