import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

# Ensure local imports work
sys.path.append(os.getcwd())

try:
    import data_structures
    import core_modules
except ImportError as e:
    print("Error importing modules: " + str(e))
    sys.exit(1)

try:
    import scapy.all
except ImportError:
    messagebox.showerror("Error", "Please install scapy: pip install scapy")
    sys.exit(1)

class SimpleApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetGuard (Final Demo)")
        self.root.geometry("1100x750")
        
        self.bst = data_structures.BlacklistBST()
        self.stack = data_structures.AlertStack()
        self.graph = data_structures.NetworkGraph()
        
        # [LAB 7 & 5] Using Custom Doubly Linked List Queue
        self.pktqueue = data_structures.DoublyLinkedListQueue()
        
        self.sniffer = None
        self.detector = None
        self.is_running = False
        
        self.packet_list = [] 

        self.setup_gui()
        self.load_blacklist()

    def load_blacklist(self):
        self.bst.insert("192.168.1.100")
        self.bst.insert("10.0.0.5")

    def setup_gui(self):
        frame_top = tk.Frame(self.root, pady=10)
        frame_top.pack(fill="x")
        
        # Control Buttons
        btn_start = tk.Button(frame_top, text="Start", command=self.start, bg="green", fg="white", width=10)
        btn_start.pack(side="left", padx=5)
        
        btn_stop = tk.Button(frame_top, text="Stop", command=self.stop, bg="red", fg="white", width=10)
        btn_stop.pack(side="left", padx=5)
        
        # [LAB 11] Bubble Sort
        btn_sort_b = tk.Button(frame_top, text="Sort (Bubble)", command=self.sort_bubble, width=12)
        btn_sort_b.pack(side="left", padx=5)
        
        # [LAB 12] Merge Sort
        btn_sort_m = tk.Button(frame_top, text="Sort (Merge)", command=self.sort_merge, width=12, bg="#e0f2fe")
        btn_sort_m.pack(side="left", padx=5)
        
        # [LAB 8] View BST
        btn_bst = tk.Button(frame_top, text="View Blacklist", command=self.view_bst, width=12)
        btn_bst.pack(side="left", padx=5)
        
        # [LAB 9] View Graph
        btn_graph = tk.Button(frame_top, text="View Graph", command=self.view_graph, width=12)
        btn_graph.pack(side="left", padx=5)

        frame_mid = tk.LabelFrame(self.root, text="Live Traffic (DLL Queue)")
        frame_mid.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("Source", "Destination", "Protocol", "Size")
        self.table = ttk.Treeview(frame_mid, columns=columns, show="headings", height=15)
        
        self.table.heading("Source", text="Source IP")
        self.table.heading("Destination", text="Destination IP")
        self.table.heading("Protocol", text="Protocol")
        self.table.heading("Size", text="Packet Size")
        self.table.column("Source", width=150)
        self.table.column("Destination", width=150)
        self.table.column("Protocol", width=80)
        self.table.column("Size", width=80)
        
        self.table.pack(fill="both", expand=True)

        frame_bot = tk.LabelFrame(self.root, text="Alerts (Stack)")
        frame_bot.pack(fill="x", padx=10, pady=10)
        
        self.alert_box = tk.Listbox(frame_bot, height=8, fg="red", font=("Consolas", 10))
        self.alert_box.pack(side="left", fill="x", expand=True)
        
        btn_unblock = tk.Button(frame_bot, text="Unblock IP", command=self.unblock_ip)
        btn_unblock.pack(side="right", padx=10)

    def start(self):
        if self.is_running: return
        self.is_running = True
        print("System Started")
        self.sniffer = core_modules.PacketCaptureThread(self.pktqueue)
        self.detector = core_modules.DetectionEngine(
            self.pktqueue, self.update_gui, self.bst, self.stack, analyze_local=False 
        )
        self.sniffer.start()
        self.detector.start()

    def stop(self):
        self.is_running = False
        print("System Stopped")
        if self.sniffer: self.sniffer.stop()
        if self.detector: self.detector.stop()

    def update_gui(self, type, data):
        self.root.after(0, lambda: self.process_gui_data(type, data))

    def process_gui_data(self, type, data):
        if not self.is_running: return

        if type == "TRAFFIC":
            if len(data) >= 5:
                src, dst = data[0], data[2]
                proto, size = data[3], data[4]
                
                # Update Graph
                self.graph.addconnection(src, dst)
                
                self.table.insert("", 0, values=(src, dst, proto, size))
                self.packet_list.append((src, dst, proto, size))
                if len(self.table.get_children()) > 50:
                    self.table.delete(self.table.get_children()[-1])

        elif type == "ALERT":
            src, reason, severity = data
            text = f"[{severity}] BLOCKED {src}: {reason}"
            self.alert_box.insert(0, text)

    def unblock_ip(self):
        selected = self.alert_box.curselection()
        if not selected: return
        text = self.alert_box.get(selected[0])
        parts = text.split()
        if len(parts) > 2:
            ip = parts[2].replace(":", "")
            if self.detector: self.detector.unblock_ip(ip)
            else: core_modules.FirewallManager.unblock_ip(ip)
            messagebox.showinfo("Success", "Unblocked IP: " + ip)
            self.alert_box.delete(selected[0])

    # LAB 11: Bubble Sort (O(n^2))
    def sort_bubble(self):
        data = self.packet_list[:]
        n = len(data)
        for i in range(n):
            for j in range(0, n - i - 1):
                if data[j][3] < data[j+1][3]: # Descending
                    data[j], data[j+1] = data[j+1], data[j]
        self.refresh_table(data)
        messagebox.showinfo("Sorted", "Bubble Sort Complete (O(n^2))")

    # LAB 12: Merge Sort (O(n log n))
    def sort_merge(self):
        data = self.packet_list[:]
        sorted_data = data_structures.merge_sort(data)
        self.refresh_table(sorted_data)
        messagebox.showinfo("Sorted", "Merge Sort Complete (O(n log n))")

    def refresh_table(self, data):
        for item in self.table.get_children():
            self.table.delete(item)
        for row in data:
            self.table.insert("", "end", values=row)
    
    # LAB 8: View BST
    def view_bst(self):
        ips = self.bst.get_all_ips()
        messagebox.showinfo("Blacklist (BST In-Order)", "\n".join(ips) if ips else "Empty")

    # LAB 9: View Graph
    def view_graph(self):
        conns = self.graph.get_connections()
        text = ""
        for src, dsts in conns.items():
            text += f"{src} -> {list(dsts)}\n"
        messagebox.showinfo("Network Graph (Adj List)", text if text else "No Connections")

if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleApp(root)
    root.mainloop()
