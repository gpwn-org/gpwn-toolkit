# GPWN Toolkit

A collection of libraries and a TUI to test fiber GPON deployments.

> **Authorized security research only.** GPWN is intended solely for security
> research on test deployments. Use it only when you own the deployment or have
> explicit authorization from its owner to test that specific deployment. Do
> not use GPWN for unauthorized access, interception, disruption, or any other
> illegal activity. You are responsible for understanding and following all
> laws and regulations that apply where you conduct the research.

## Features

- Manage a connected ONU, view its state and configuration
- Autoscan GPON gem ports
- Record traffic
- Visualize traffic

## Hardware required

1. An ONU based on a Realtek 960x chipset, some confirmed working examples:

   - [HSGQ XPON Stick](https://www.hsgq.com/XPON-Stick-Full-Form-Customized-pd597593578.html)
   - [ODI XPON Stick](https://www.aliexpress.us/item/3256809370622026.html)
     

2. Optionally, a media converter for SFP <-> RJ45

   - like: [TP-Link MC220L](https://www.amazon.com/dp/B003CFATL0)

## Usage

1. Connect the ONU to the computer / network
2. Start the TUI with `cargo run`
3. Enter SSH credentials to connect to the ONU

There are 3 pages:

1. **Monitor** - This will list the state of the ONU, including:

   - operational status and configuration
   - downstream and upstream flows
   - gem port activity / flow statistics

2. **Autoscan** - Scan for in-use GEM ports

   1. switch to the second tab by pressing `2`
   2. Set the start and end ports and start scan
   3. When complete, optionally add all found ports as downstream flows with `A`
   4. Switch back to the Monitor tab by pressing `1`

3. **MIB** - View the MIB (Management Information Base) of the ONU

## Record

Once per ONU start, press `Shift` + `L` to configure the ONU to go passive (i.e. turn off the laser) and forward all traffic.

Then, press `Ctrl` + `R` to start recording traffic to a file.

This will save a pcap file which can be viewed in Wireshark, or...

## Visualize

Use the `gpwn-visualize` tool to visualize the data.

Start the analyzer with:
```sh
cargo run -p gpwn-pcap-analyzer /path/to/recording.pcapng --artifact-dir /path/to/artifacts/dir
```

This will parse the capture file and serve data as an API for the visualizer.

Start the web-based visualizer with:
```sh
cd gpwn-visualize
bun run build    # once is enough
bun run start
```

And open the URL in your favorite browser.

## License

GPWN Toolkit is licensed under the [GNU General Public License version 3](LICENSE).
