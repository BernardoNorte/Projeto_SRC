import threading
from flask import Flask, jsonify
from scapy.all import sniff
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText

# Configuração do Flask
app = Flask(__name__)
captured_packets = []  # Lista para armazenar os pacotes capturados

# Função para capturar pacotes
def capture_packets():
    def process_packet(packet):
        captured_packets.append(packet.summary())  # Salva o resumo do pacote
        update_gui(packet.summary())  # Atualiza a interface do Tkinter

    sniff(count=10, prn=process_packet)  # Captura 10 pacotes

# Endpoint para acessar os pacotes capturados via API
@app.route('/packets', methods=['GET'])
def get_packets():
    return jsonify(captured_packets)

# Configuração do Tkinter com ttkbootstrap
root = ttk.Window(themename="darkly")  # Tema Dark
root.title("Captura de Pacotes - Dark Mode")
root.geometry("700x500")

# Título
title_label = ttk.Label(
    root, text="Captura de Pacotes de Rede", font=("Helvetica", 16), bootstyle="inverse-primary"
)
title_label.pack(pady=10)

# Área de texto para exibir os pacotes
text_area = ScrolledText(root, height=20, width=80, bootstyle="dark")
text_area.pack(pady=10)

# Botão para iniciar a captura
def start_capture():
    threading.Thread(target=capture_packets, daemon=True).start()

btn_capture = ttk.Button(root, text="Iniciar Captura", bootstyle="success-outline", command=start_capture)
btn_capture.pack(pady=10)

# Função para atualizar a interface do Tkinter
def update_gui(packet_summary):
    text_area.insert(END, f"{packet_summary}\n")
    text_area.see(END)

# Função para executar o Flask em uma thread separada
def run_flask():
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)

# Iniciando o Flask em uma thread
flask_thread = threading.Thread(target=run_flask, daemon=True)
flask_thread.start()

# Iniciando a interface Tkinter
root.mainloop()
