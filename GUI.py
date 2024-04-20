from tkinter import filedialog

import customtkinter
from tabulate import tabulate

from Functions import *
from functionsCSV import *
from neuron import *

customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("blue")

FILEPATH = ""
PCAP_RELATIVE_FILEPATH = 'pcap\\temp.pcap'
CSV_RELATIVE_FILEPATH = 'csv\\temp.csv'
CSV_HASHED_FILEPATH = 'csv\\hashed\\temp.csv'
FILE_CONTENT = b''
RUN_STATE = 0  # 0=Locked, 1=Loaded, 2=Record
INTERFACES = []
TIME_START = 5
TIME_END = 60


class App(customtkinter.CTk):

    # ======================
    #      FUNCTIONS
    # ======================
    def change_appearance_mode_event(self, new_appearance_mode: str):
        """
        Change the appearance mode of the application.

        Args:
            new_appearance_mode (str): The new appearance mode to set.
        """
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        """
        Change the scaling of widgets in the application.

        Args:
            new_scaling (str): The new scaling percentage to set.
        """
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)

    def update_entry_state(self):
        """
        Updates the state and content of the load entry widget after inserting path to a file.
        """
        global FILEPATH
        if FILEPATH != '':
            self.load_entry.configure(state="normal")
            self.load_entry.delete(0, "end")
            self.load_entry.insert(0, path_formatted(FILEPATH))
            self.load_entry.configure(state="readonly")

    def load_pcap(self):
        """
        Loads a file, updates the GUI Run button state, and prepares for running.

        """
        global FILEPATH
        global FILE_CONTENT
        global RUN_STATE
        new_filepath = filedialog.askopenfilename()
        print("Selected file: ", new_filepath)
        file = load_pcap_file(new_filepath)
        if file:
            FILEPATH = new_filepath
            FILE_CONTENT = file
            self.update_entry_state()
            self.run_button.configure(state="normal")
            self.run_button.configure(text="Analyze Loaded")
            RUN_STATE = 1

    def record_file(self):
        """
        Records packets from the specified interface for a given time duration.
        """
        global RUN_STATE, FILE_CONTENT
        interface_name = self.interface_combobox.get()
        run_time = self.time_slider.get()  # float
        capture_size, FILE_CONTENT = capture_packets(interface_name, run_time)
        self.run_button.configure(state="normal")
        self.run_button.configure(text="Analyze Recorded")
        RUN_STATE = 2

    def write_table_protocols(self, protocols_count):
        """
        Writes the protocols and their occurrences to a textbox.

        Args:
            protocols_count (dict): A dictionary containing the count of occurrences of each protocol.

        Returns:
            None
        """
        protocols = list(protocols_count.items())
        protocols_table = tabulate(protocols, headers=["Protocol", "Occurrence"], tablefmt="plain",
                                   numalign="right")
        print(protocols_table)
        self.protocols_textbox1.configure(state="normal")
        self.protocols_textbox1.delete("0.0", "end")
        self.protocols_textbox1.insert("0.0", protocols_table)
        self.protocols_textbox1.configure(state="disabled")

    def write_table_packet_size(self, packet_sizes):
        packets_table = tabulate(packet_sizes, headers=["Packet size", "Occurrence"], tablefmt="plain",
                                 numalign="right")
        print(packets_table)
        self.packet_size_textbox1.configure(state="normal")
        self.packet_size_textbox1.delete("0.0", "end")
        self.packet_size_textbox1.insert("0.0", packets_table)
        self.packet_size_textbox1.configure(state="disabled")

    def write_table_src_dst(self, src_dst):
        src_dst_table = tabulate(src_dst, headers=["Src & Dst", "Occurrence"], tablefmt="plain", numalign="right")
        print(src_dst_table)
        self.src_dst_textbox1.configure(state="normal")
        self.src_dst_textbox1.delete("0.0", "end")
        self.src_dst_textbox1.insert("0.0", src_dst_table)
        self.src_dst_textbox1.configure(state="disabled")

    def statistics(self):
        # percentage of vpn packets
        number_of_encr_packets = number_of_encrypted_packets(CSV_RELATIVE_FILEPATH)
        number_of_pack = number_of_packets(CSV_RELATIVE_FILEPATH)
        percentage_of_packets_encrypted = number_of_encr_packets/number_of_pack * 100
        self.percentage_entry1.configure(state="normal")
        self.percentage_entry1.delete(0, "end")
        self.percentage_entry1.insert(0, f"{percentage_of_packets_encrypted:.2f}%")
        self.percentage_entry1.configure(state="disabled")

        # num of all vpn packets
        packet_counter = number_of_encrypted_packets(CSV_RELATIVE_FILEPATH)
        self.number_of_packets_entry1.configure(state="normal")
        self.number_of_packets_entry1.delete(0, "end")
        self.number_of_packets_entry1.insert(0, str(packet_counter))
        self.number_of_packets_entry1.configure(state="disabled")

        # protocols + count
        protocols_count = count_protocols(CSV_RELATIVE_FILEPATH)
        self.write_table_protocols(protocols_count)

        # encrypted packets size + count
        packet_size = remove_extra_char(encrypted_packet_size(CSV_RELATIVE_FILEPATH))
        self.write_table_packet_size(packet_size)

        # src/dst + count
        src_dst = src_dst_encrypted_packets(CSV_RELATIVE_FILEPATH)
        self.write_table_src_dst(src_dst)

    def analyze(self):
        """
        Performs an action based on the selected traffic (loaded/recorded).
        """
        # TODO: prepsat i dokumentaci
        global FILE_CONTENT
        if RUN_STATE == 1 or RUN_STATE == 2:  # load & record
            pcap_file = FILE_CONTENT
            save_file(pcap_file, get_root_folder() + '\\' + PCAP_RELATIVE_FILEPATH)
            convertPcapToCSV(PCAP_RELATIVE_FILEPATH, CSV_RELATIVE_FILEPATH)
            hashValues(CSV_RELATIVE_FILEPATH, CSV_HASHED_FILEPATH)
            encrypted = evaluation(CSV_HASHED_FILEPATH, get_root_folder() + '\\tfmodel1.h5')
            addColumn(CSV_RELATIVE_FILEPATH,'encrypted', encrypted)
            self.statistics()  # naplneni statistic
        else:
            return

    def get_slider(self, value):
        """
        Updates the time label text with the specified value from the slider.

        Args:
            value (int): The value to display on the label.
        """
        self.time_label.configure(text=(str(value) + " s"))

    def __init__(self):
        super().__init__()
        global TIME_START
        global TIME_END
        global INTERFACES

        # ======================
        #    configure window
        # ======================
        self.title("Encrypted Traffic Analysis")
        self.geometry(f"{1200}x{800}")
        INTERFACES = get_interfaces()

        # ======================
        #    configure grid layout (4x4)
        # ======================
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # ======================
        #    CONFIG - sidebar
        # ======================
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=6, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)

        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="Encrypted Traffic Analysis",
                                                 font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # LOAD
        self.load_button = customtkinter.CTkButton(self.sidebar_frame, text="Load Traffic", command=self.load_pcap)
        self.load_button.grid(row=1, column=0, padx=20, pady=10)

        self.load_entry = customtkinter.CTkEntry(self.sidebar_frame, placeholder_text="Loaded File", state="readonly")
        self.load_entry.grid(row=2, column=0, padx=20, pady=10)

        # RECORD
        self.record_button = customtkinter.CTkButton(self.sidebar_frame, text="Record Traffic",
                                                     command=self.record_file)
        self.record_button.grid(row=3, column=0, padx=20, pady=10)

        self.interface_combobox = customtkinter.CTkComboBox(self.sidebar_frame,
                                                            values=INTERFACES, state="readonly")
        self.interface_combobox.grid(row=4, column=0, padx=20, pady=(10, 10))

        self.time_slider = customtkinter.CTkSlider(self.sidebar_frame, from_=TIME_START, to=TIME_END,
                                                   number_of_steps=TIME_END - TIME_START, command=self.get_slider)

        self.time_slider.grid(row=5, column=0, padx=20, pady=10)
        self.time_label = customtkinter.CTkLabel(self.sidebar_frame, text=f"{TIME_START} s")
        self.time_label.grid(row=6, column=0, padx=20, pady=10)

        # ======================
        #    main run button
        # ======================
        self.run_button = customtkinter.CTkButton(self.sidebar_frame, text="Analyze", state="disabled", command=self.analyze)
        self.run_button.grid(row=7, column=0, padx=20, pady=10)

        # ======================
        #      APPEARANCE
        # ======================
        self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=9, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame,
                                                                       values=["Light", "Dark", "System"],
                                                                       command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=10, column=0, padx=20, pady=(10, 10))
        self.scaling_label = customtkinter.CTkLabel(self.sidebar_frame, text="UI Scaling:", anchor="w")
        self.scaling_label.grid(row=11, column=0, padx=20, pady=(10, 0))
        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame,
                                                               values=["80%", "90%", "100%", "110%", "120%"],
                                                               command=self.change_scaling_event)
        self.scaling_optionemenu.grid(row=12, column=0, padx=20, pady=(10, 20))

        # ======================
        #      DESCRIPTION
        # ======================
        self.describtion_label = customtkinter.CTkLabel(self, text="Description", anchor="w",
                                                        font=customtkinter.CTkFont(size=15, weight="bold"))
        self.describtion_label.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.description_textbox = customtkinter.CTkTextbox(self, width=250, height=100)
        self.description_textbox.grid(row=1, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")

        # ======================
        #    STATISTICS
        # ======================
        self.statistics_label = customtkinter.CTkLabel(self, text="Statistics", anchor="w",
                                                       font=customtkinter.CTkFont(size=15, weight="bold"))
        self.statistics_label.grid(row=2, column=1, padx=20, pady=(20, 10))

        self.statistics_tableview = customtkinter.CTkTabview(self, width=250)
        self.statistics_tableview.grid(row=3, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")

        self.statistics_tableview.add("General")
        self.statistics_tableview.add("Protocols")
        self.statistics_tableview.add("Packets Size")
        self.statistics_tableview.add("Source/Destination")

        self.statistics_tableview.tab("General").grid_rowconfigure(2)
        self.statistics_tableview.tab("Protocols")
        self.statistics_tableview.tab("Packets Size")
        self.statistics_tableview.tab("Source/Destination")

        self.percentage_label1 = customtkinter.CTkLabel(self.statistics_tableview.tab("General"),
                                                        text="Percentage of VPN packets:")
        self.percentage_label1.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.percentage_entry1 = customtkinter.CTkEntry(self.statistics_tableview.tab("General"), state="readonly")
        self.percentage_entry1.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.number_of_packets_label1 = customtkinter.CTkLabel(self.statistics_tableview.tab("General"),
                                                               text="Number of all VPN packets:")
        self.number_of_packets_label1.grid(row=1, column=0, padx=20, pady=(20, 10))

        self.number_of_packets_entry1 = customtkinter.CTkEntry(self.statistics_tableview.tab("General"),
                                                               state="readonly")
        self.number_of_packets_entry1.grid(row=1, column=1, padx=20, pady=(20, 10))

        self.protocols_textbox1 = customtkinter.CTkTextbox(self.statistics_tableview.tab("Protocols"), width=700,
                                                           height=150, state="disabled")
        self.protocols_textbox1.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.packet_size_textbox1 = customtkinter.CTkTextbox(self.statistics_tableview.tab("Packets Size"), width=700,
                                                             height=150, state="disabled")
        self.packet_size_textbox1.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.src_dst_textbox1 = customtkinter.CTkTextbox(self.statistics_tableview.tab("Source/Destination"), width=700,
                                                         height=150, state="disabled")
        self.src_dst_textbox1.grid(row=0, column=0, padx=20, pady=(20, 10))

        # ======================
        #      COULD BE ENCRYPTED
        # ======================
        self.irregularity_label = customtkinter.CTkLabel(self, text="Could be encrypted", anchor="w",
                                                         font=customtkinter.CTkFont(size=15, weight="bold"))
        self.irregularity_label.grid(row=4, column=1, padx=20, pady=(20, 10))

        self.irregularity_tableview = customtkinter.CTkTabview(self, width=250)
        self.irregularity_tableview.grid(row=5, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")

        self.irregularity_tableview.add("General")
        self.irregularity_tableview.add("Protocols")
        self.irregularity_tableview.add("Packet Size")
        self.irregularity_tableview.add("Source/Destination")

        self.irregularity_tableview.tab("General").grid_rowconfigure(2)
        self.irregularity_tableview.tab("Protocols")
        self.irregularity_tableview.tab("Packet Size")
        self.irregularity_tableview.tab("Source/Destination")

        self.percentage_label2 = customtkinter.CTkLabel(self.irregularity_tableview.tab("General"),
                                                        text="Percentage of VPN packets:")
        self.percentage_label2.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.percentage_entry2 = customtkinter.CTkEntry(self.irregularity_tableview.tab("General"), state="disabled")
        self.percentage_entry2.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.number_of_packets_label2 = customtkinter.CTkLabel(self.irregularity_tableview.tab("General"),
                                                               text="Number of all packets:")
        self.number_of_packets_label2.grid(row=1, column=0, padx=20, pady=(20, 10))

        self.number_of_packets_entry2 = customtkinter.CTkEntry(self.irregularity_tableview.tab("General"),
                                                               state="disabled")
        self.number_of_packets_entry2.grid(row=1, column=1, padx=20, pady=(20, 10))

        self.protocols_textbox2 = customtkinter.CTkTextbox(self.irregularity_tableview.tab("Protocols"), width=700,
                                                           height=150)
        self.protocols_textbox2.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.packet_size_textbox2 = customtkinter.CTkTextbox(self.irregularity_tableview.tab("Packet Size"), width=700,
                                                             height=150)
        self.packet_size_textbox2.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.src_dst_textbox2 = customtkinter.CTkTextbox(self.irregularity_tableview.tab("Source/Destination"),
                                                         width=700,
                                                         height=150)
        self.src_dst_textbox2.grid(row=0, column=0, padx=20, pady=(20, 10))

        # ======================
        #   set default values
        # ======================
        self.time_slider.set(TIME_START)
        self.interface_combobox.set("Ethernet")
        self.appearance_mode_optionemenu.set("System")
        self.scaling_optionemenu.set("100%")
        self.description_textbox.insert("0.0", "Design and program an application that will detect "
                                               "encrypted traffic on the network and display its "
                                               "percentage of the total traffic on the network. The "
                                               "application will produce clear statistics on the "
                                               "protocol used, origin/destination, size of encrypted "
                                               "packets, and total amount of encrypted data on the "
                                               "network. The application will also detect packets on the "
                                               "network that could be encrypted from a security "
                                               "perspective but are not. The application will build a "
                                               "picture of the normal traffic on the network and detect "
                                               "any deviations that occur (change in encrypted packet "
                                               "size, total amount of encrypted data, protocols, "
                                               "source/destination addresses, etc.). Simulate different "
                                               "network traffic scenarios and test the developed "
                                               "application on them.\n\n")
        self.description_textbox.configure(state="disabled")


if __name__ == "__main__":
    # pydoc.writedoc('GUI')
    app = App()
    app.mainloop()
    # TODO: clear a folder with temp siles
