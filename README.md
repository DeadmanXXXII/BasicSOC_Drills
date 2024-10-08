# BasicSOC_Drills

For you analysts that slave over a remote cloud SOC and you can focus on the more fun things than simple routines when your under attack or a red op.

Fill in the placeholders and implement for the specific sections and tools you have:

zap, Nmap, nessus, snort, surricata, Wireshark, md5house,crackstaion, exploit database, dark stack overflow, windows, Linux, AWS, Azure, GCP 
all work and connect correctly using the IDE rust up and loaded as a cargo.toml and run once you have configured it correctly to your systems specs.

Here is how to do that in Kali which is how I run these tools.

The provided code for Basic-SOCDrills does indeed feature an interactive GUI using GTK, and it can be run on a Kali Linux system. Here’s how you can set it up and run it:

### Prerequisites:
1. **Install Rust:**
   Make sure Rust is installed on your system. You can install it by running:

   ```bash

   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```
### Gtk:
2. **Install GTK and other dependencies:**
   Since the project uses GTK for the GUI, you need to have the GTK development libraries installed:

   ```bash
   sudo apt update
   sudo apt install libgtk-3-dev
   sudo apt install clamav nmap macchanger logrotate
   ```

### Running the Project:
1. **Create a new Rust project (if you haven't already):**

   ```bash
   cargo new basic-soc-drills
   cd basic-soc-drills
   ```

2. **Replace the `main.rs` content:**
   Open the `src/main.rs` file and replace its content with the provided code.

3. **Add dependencies to `Cargo.toml`:**
   Open the `Cargo.toml` file and add the required dependencies:

   ```bash
   toml
   [dependencies]
   cron = "0.6"
   gtk = "0.9"
   ```

4. **Build and Run the Project:**
   Use the following commands to build and run your project:

   ```bash

   cargo build
   cargo run

   ```

### Potential Issues and Solutions:
- **Permissions:**
  Some operations, like updating antivirus definitions or changing MAC addresses, require superuser privileges. You might need to run the compiled binary with `sudo`:

  ```bash

  sudo ./target/debug/basic-soc-drills

  ```

- **Dependencies:**

  Ensure all dependencies are installed correctly. If any library is missing, install it using `apt` or the appropriate package manager.

### Explanation of GUI Integration:
- **GTK Application:**
  The code initializes a GTK application and sets up an application window with a label. The label displays "Defense System is running...".
  
- **Multithreading:**
  The code uses multiple threads to handle different SOC tasks concurrently. Alerts are sent via an `mpsc` channel to the GUI thread, which displays alerts.

- **Periodic Checks:**
  Each thread runs in an infinite loop, periodically performing its assigned tasks and sleeping for a specific duration between iterations.

### Summary:
The provided code sets up a basic security operations center (SOC) drill system with a GTK-based GUI. It includes functions for various security tasks and runs on a multi-threaded architecture. By following the steps outlined above, you can build and run this application in Kali Linux.
