from tkinter import filedialog
import customtkinter

customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("blue")
filepath = ""


def open_input_dialog_event():
    dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
    print("CTkInputDialog:", dialog.get_input())


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # configure window
        self.title("Encrypted Traffic Analysis")
        self.geometry(f"{1200}x{800}")

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # create sidebar frame with widgets - CONFIG
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=6, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="Encrypted Traffic Analysis",
                                                 font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.load_button = customtkinter.CTkButton(self.sidebar_frame, text="Load Traffic", command=self.load_file)
        self.load_button.grid(row=1, column=0, padx=20, pady=10)

        self.load_entry = customtkinter.CTkEntry(self.sidebar_frame, placeholder_text="Loaded File")
        self.load_entry.grid(row=2, column=0, padx=20, pady=10)

        self.record_button = customtkinter.CTkButton(self.sidebar_frame, text="Record Traffic",
                                                     command=self.sidebar_button_event)
        self.record_button.grid(row=3, column=0, padx=20, pady=10)

        self.interface_entry = customtkinter.CTkEntry(self.sidebar_frame, placeholder_text="interface")
        self.interface_entry.grid(row=4, column=0, padx=20, pady=10)
        self.interface_entry.bind("<KeyRelease>", lambda event: self.update_button_state())

        self.time_entry = customtkinter.CTkEntry(self.sidebar_frame, placeholder_text="time [s]")
        self.time_entry.grid(row=5, column=0, padx=20, pady=10)
        self.time_entry.bind("<KeyRelease>", lambda event: self.update_button_state())

        self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=7, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame,
                                                                       values=["Light", "Dark", "System"],
                                                                       command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=8, column=0, padx=20, pady=(10, 10))
        self.scaling_label = customtkinter.CTkLabel(self.sidebar_frame, text="UI Scaling:", anchor="w")
        self.scaling_label.grid(row=9, column=0, padx=20, pady=(10, 0))
        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame,
                                                               values=["80%", "90%", "100%", "110%", "120%"],
                                                               command=self.change_scaling_event)
        self.scaling_optionemenu.grid(row=10, column=0, padx=20, pady=(10, 20))

        # create textbox - DESCRIPTION
        self.describtion_label = customtkinter.CTkLabel(self, text="Description", anchor="w",
                                                        font=customtkinter.CTkFont(size=15, weight="bold"))
        self.describtion_label.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.description_textbox = customtkinter.CTkTextbox(self, width=250, height=100)
        self.description_textbox.grid(row=1, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")

        # create tabview - STATISTICS
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

        self.percentage_label = customtkinter.CTkLabel(self.statistics_tableview.tab("General"),
                                                       text="Percentage of VPN packets:")
        self.percentage_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.percentage_entry = customtkinter.CTkEntry(self.statistics_tableview.tab("General"), state="readonly")
        self.percentage_entry.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.number_of_packets_label = customtkinter.CTkLabel(self.statistics_tableview.tab("General"),
                                                              text="Number of all packets:")
        self.number_of_packets_label.grid(row=1, column=0, padx=20, pady=(20, 10))

        self.number_of_packets_entry = customtkinter.CTkEntry(self.statistics_tableview.tab("General"),
                                                              state="readonly")
        self.number_of_packets_entry.grid(row=1, column=1, padx=20, pady=(20, 10))

        self.protocols_textbox = customtkinter.CTkTextbox(self.statistics_tableview.tab("Protocols"), width=700,
                                                          height=150)
        self.protocols_textbox.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.packet_size_textbox = customtkinter.CTkTextbox(self.statistics_tableview.tab("Packet Size"), width=700,
                                                            height=150)
        self.packet_size_textbox.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.src_dst_textbox = customtkinter.CTkTextbox(self.statistics_tableview.tab("Source/Destination"), width=700,
                                                        height=150)
        self.src_dst_textbox.grid(row=0, column=0, padx=20, pady=(20, 10))

        # create tabview - IRREGULARITY
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

        self.percentage_label = customtkinter.CTkLabel(self.irregularity_tableview.tab("General"),
                                                       text="Percentage of VPN packets:")
        self.percentage_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.percentage_entry = customtkinter.CTkEntry(self.irregularity_tableview.tab("General"), state="readonly")
        self.percentage_entry.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.number_of_packets_label = customtkinter.CTkLabel(self.irregularity_tableview.tab("General"),
                                                              text="Number of all packets:")
        self.number_of_packets_label.grid(row=1, column=0, padx=20, pady=(20, 10))

        self.number_of_packets_entry = customtkinter.CTkEntry(self.irregularity_tableview.tab("General"),
                                                              state="readonly")
        self.number_of_packets_entry.grid(row=1, column=1, padx=20, pady=(20, 10))

        self.protocols_textbox = customtkinter.CTkTextbox(self.irregularity_tableview.tab("Protocols"), width=700,
                                                          height=150)
        self.protocols_textbox.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.packet_size_textbox = customtkinter.CTkTextbox(self.irregularity_tableview.tab("Packet Size"), width=700,
                                                            height=150)
        self.packet_size_textbox.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.src_dst_textbox = customtkinter.CTkTextbox(self.irregularity_tableview.tab("Source/Destination"),
                                                        width=700,
                                                        height=150)
        self.src_dst_textbox.grid(row=0, column=0, padx=20, pady=(20, 10))

        # set default values
        self.load_entry.configure(state="readonly")
        self.record_button.configure(state="disabled")
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
        self.protocols_textbox.insert("0.0", "Protocols\n\n")
        self.packet_size_textbox.insert("0.0", "Packet Size\n\n")
        self.src_dst_textbox.insert("0.0", "Source/Destination\n\n")

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)

    def sidebar_button_event(self):
        print("sidebar_button click")

    def path_formatted(self, path):
        path_parts = path.split("/")
        file_name = path_parts[-1]
        return file_name

    def update_button_state(self):
        if (self.interface_entry.get()) == "" or (self.time_entry.get()) == "":
            self.record_button.configure(state="disabled")
        else:
            self.record_button.configure(state="normal")

    def update_entry_state(self):
        global filepath
        if filepath != '':
            self.load_entry.configure(state="normal")
            index = len(self.load_entry.get())
            self.load_entry.delete(0, index)
            self.load_entry.insert(0, self.path_formatted(filepath))
            self.load_entry.configure(state="readonly")

    def load_file(self):
        global filepath
        filepath = filedialog.askopenfilename()
        print("Selected file: ", filepath)
        self.update_entry_state()


if __name__ == "__main__":
    app = App()
    app.mainloop()
