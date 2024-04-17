from tkinter import filedialog
import customtkinter
import psutil
import os
import pyshark
import sys
import pydoc

customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("blue")

filepath = ""
file_content = ""
run_state = 0  # 0=Locked, 1=Loaded, 2=Record
interfaces = []
time_start = 5
time_end = 60


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

    def path_formatted(self, path):
        """
        Extracts the file name from a given path.

        Args:
            path (str): The path from which to extract the file name.

        Returns:
            str: The extracted file name.
        """
        path_parts = path.split("/")
        file_name = path_parts[-1]
        return file_name

    def update_entry_state(self):
        """
        Updates the state and content of the load entry widget after inserting path to a file.
        """
        global filepath
        if filepath != '':
            self.load_entry.configure(state="normal")
            index = len(self.load_entry.get())
            self.load_entry.delete(0, index)
            self.load_entry.insert(0, self.path_formatted(filepath))
            self.load_entry.configure(state="readonly")

    def open_file(self, path):
        """
        Opens and reads the content of a file.

        Args:
            path (str): The path of the file to be opened and read.

        Returns:
            bytes: The content of the file as a byte string.
                None if the file is not found or an error occurs.
        """
        try:
            with open(path, "rb") as file:
                file_content = file.read()
            return file_content
        except FileNotFoundError:
            print(f"File {path} not found.")
            return None
        except Exception as e:
            print(f"Error occurs while reading the file: {e}")
            return None

    def get_root_folder(self):
        """
        Gets the root directory of the program.

        Returns:
            str: The root directory path.
        """
        program_path = sys.argv[0]
        root_directory = os.path.dirname(program_path)
        return root_directory

    def save_file(self, file_content, file_path):
        """
        Saves content to a file.

        Args:
            file_content (bytes): The content to be saved.
            file_path (str): The path where the content will be saved.
        """
        with open(file_path, 'wb') as f:
            f.write(file_content)

    def load_file(self):
        """
        Loads a file, updates the GUI Run button state, and prepares for running.

        """
        global filepath
        global file_content
        global run_state
        new_filepath = filedialog.askopenfilename()
        print("Selected file: ", new_filepath)
        file_name, file_extension = os.path.splitext(new_filepath)
        if file_extension.lower() == ".pcap" or file_extension.lower() == ".pcapng":
            filepath = new_filepath
            file_content = self.open_file(filepath)
            self.update_entry_state()
            self.run_button.configure(state="normal")
            self.run_button.configure(text="Run Loaded")
            run_state = 1
        else:
            print("Wrong file type!")

    def capture_packets(self, interface_name, run_time):
        """
        Capture packets from the specified interface for the given time duration.

        Args:
            interface_name (str): The name of the interface to capture packets from.
            run_time (float): The duration of the capture in seconds.

        Returns:
            tuple: A tuple containing the size of the captured file and its content.
        """
        file_name = "capture.pcapng"
        capture = pyshark.LiveCapture(interface=interface_name, output_file=file_name)
        capture.set_debug()
        capture.sniff(timeout=run_time)
        capture_size = os.path.getsize(file_name)
        print("successfully captured")
        captured_file = self.open_file(self.get_root_folder() + "\\" + file_name)
        print("successfully opened")
        return capture_size, captured_file

    def record_file(self):
        """
        Records packets from the specified interface for a given time duration.
        """
        global run_state, file_content
        # TODO: dodelat funkci
        interface_name = self.interface_combobox.get()
        run_time = self.time_slider.get()  # float
        capture_size, file_content = self.capture_packets(interface_name, run_time)
        self.run_button.configure(state="normal")
        self.run_button.configure(text="Run Recorded")
        run_state = 2

    def on_run(self):
        """
        Performs an action based on the selected traffic (loaded/recorded).
        """
        if run_state == 1 or run_state == 2:  # load & record
            global file_content
            pcap_file = file_content
            #TODO: dodelat a prepsat i dokumentaci
            self.save_file(pcap_file, 'C:\\Users\\fisar\\Downloads\\test.pcap')
        else:
            return

    def get_interfaces(self):
        """
        Retrieves a list of available network interfaces.

        Returns:
            list: A list of interface names.
        """
        interfaces = psutil.net_if_addrs()
        inters = []
        for interface_name, addresses in interfaces.items():
            inters.append(interface_name)
        return inters

    def get_slider(self, value):
        """
        Updates the time label text with the specified value from the slider.

        Args:
            value (int): The value to display on the label.
        """
        self.time_label.configure(text=(str(value) + " s"))


    def __init__(self):
        super().__init__()

        # ======================
        #    configure window
        # ======================
        self.title("Encrypted Traffic Analysis")
        self.geometry(f"{1200}x{800}")
        global time_start
        global time_end
        global interfaces
        interfaces = self.get_interfaces()

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
        self.load_button = customtkinter.CTkButton(self.sidebar_frame, text="Load Traffic", command=self.load_file)
        self.load_button.grid(row=1, column=0, padx=20, pady=10)

        self.load_entry = customtkinter.CTkEntry(self.sidebar_frame, placeholder_text="Loaded File")
        self.load_entry.grid(row=2, column=0, padx=20, pady=10)

        # RECORD
        self.record_button = customtkinter.CTkButton(self.sidebar_frame, text="Record Traffic",
                                                     command=self.record_file)
        self.record_button.grid(row=3, column=0, padx=20, pady=10)

        self.interface_combobox = customtkinter.CTkComboBox(self.sidebar_frame,
                                                            values=interfaces, state="readonly")
        self.interface_combobox.grid(row=4, column=0, padx=20, pady=(10, 10))

        self.time_slider = customtkinter.CTkSlider(self.sidebar_frame, from_=time_start, to=time_end,
                                                   number_of_steps=time_end - time_start, command=self.get_slider)

        self.time_slider.grid(row=5, column=0, padx=20, pady=10)
        self.time_label = customtkinter.CTkLabel(self.sidebar_frame, text=f"{time_start} s")
        self.time_label.grid(row=6, column=0, padx=20, pady=10)

        # ======================
        #    main run button
        # ======================
        self.run_button = customtkinter.CTkButton(self.sidebar_frame, text="Run", command=self.on_run)
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
        self.statistics_tableview.add("Packet Size")
        self.statistics_tableview.add("Source/Destination")

        self.statistics_tableview.tab("General").grid_rowconfigure(2)
        self.statistics_tableview.tab("Protocols")
        self.statistics_tableview.tab("Packet Size")
        self.statistics_tableview.tab("Source/Destination")

        self.percentage_label1 = customtkinter.CTkLabel(self.statistics_tableview.tab("General"),
                                                        text="Percentage of VPN packets:")
        self.percentage_label1.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.percentage_entry1 = customtkinter.CTkEntry(self.statistics_tableview.tab("General"), state="readonly")
        self.percentage_entry1.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.number_of_packets_label1 = customtkinter.CTkLabel(self.statistics_tableview.tab("General"),
                                                               text="Number of all packets:")
        self.number_of_packets_label1.grid(row=1, column=0, padx=20, pady=(20, 10))

        self.number_of_packets_entry1 = customtkinter.CTkEntry(self.statistics_tableview.tab("General"),
                                                               state="readonly")
        self.number_of_packets_entry1.grid(row=1, column=1, padx=20, pady=(20, 10))

        self.protocols_textbox1 = customtkinter.CTkTextbox(self.statistics_tableview.tab("Protocols"), width=700,
                                                           height=150)
        self.protocols_textbox1.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.packet_size_textbox1 = customtkinter.CTkTextbox(self.statistics_tableview.tab("Packet Size"), width=700,
                                                             height=150)
        self.packet_size_textbox1.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.src_dst_textbox1 = customtkinter.CTkTextbox(self.statistics_tableview.tab("Source/Destination"), width=700,
                                                         height=150)
        self.src_dst_textbox1.grid(row=0, column=0, padx=20, pady=(20, 10))

        # ======================
        #      IRREGULARITY
        # ======================
        self.irregularity_label = customtkinter.CTkLabel(self, text="Irregularity", anchor="w",
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

        self.percentage_entry2 = customtkinter.CTkEntry(self.irregularity_tableview.tab("General"), state="readonly")
        self.percentage_entry2.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.number_of_packets_label2 = customtkinter.CTkLabel(self.irregularity_tableview.tab("General"),
                                                               text="Number of all packets:")
        self.number_of_packets_label2.grid(row=1, column=0, padx=20, pady=(20, 10))

        self.number_of_packets_entry2 = customtkinter.CTkEntry(self.irregularity_tableview.tab("General"),
                                                               state="readonly")
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
        self.load_entry.configure(state="readonly")
        self.time_slider.set(time_start)
        self.interface_combobox.set("Ethernet")
        self.run_button.configure(state="disabled")
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
        self.protocols_textbox1.insert("0.0", "Protocols\n\n")
        self.packet_size_textbox1.insert("0.0", "Packet Size\n\n")
        self.src_dst_textbox1.insert("0.0", "Source/Destination\n\n")
        self.protocols_textbox2.insert("0.0", "Protocols\n\n")
        self.packet_size_textbox2.insert("0.0", "Packet Size\n\n")
        self.src_dst_textbox2.insert("0.0", "Source/Destination\n\n")

if __name__ == "__main__":
    #pydoc.writedoc('GUI')
    app = App()
    app.mainloop()



