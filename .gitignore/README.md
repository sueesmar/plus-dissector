# Usage of the Wireshark dissector for PLUS
The next few sections describe the installation and usage of the PLUS dissector for Wireshark.

## Installation of PLUS dissector
1. Download and install a recent version of [Wireshark](https://www.wireshark.org).
2. Open Wireshark.
3. Looking for the path to the plugins in Wireshark by menu `Help` > `About Wireshark` > `Folders`.
4. Open or create the folder for the `Personal Plugins`, got from the step before.
5. Copy the Lua script `plus.lua` for the PLUS Wireshark dissector into the `Personal Plugins` folder.
6. Restart Wireshark to activate the plugin. No error message at start may appear.
7. To check the activation of the plugin, open menu `Help` > `About Wireshark` > `Plugins` and search for the `plus.lua` plugin.

## Installation of PLUS dissector with QUIC transport layer
It is the same procedure as in the [section](#installation-of-plus-dissector) before, but instead of copy the Lua script `plus.lua`, take the file `plus_quic.lua`.

Actually, the dissection in `plus_quic.lua` is hardcoded to dissect the next layer always as QUIC, even when there isn't QUIC.

Dissectors `plus.lua` and `plus_quic.lua` can't be enabled at the same time.

## Usage of PLUS dissector
The dissector is looking for the magic id of the PLUS layer. If the magic id `0xd8007ff` is present, the dissector is automatically applied on the packet, independent of the UDP port.

To manually dissect a packet as a PLUS packet, make a right click an a packet and choose `Decode as...`. Search for the PLUS protocol and set it there.

The following filter criteria can be applied as display or capture filters for the fields of PLUS:

Filter Criteria | Description
--- | ---
plus.magic_id | Magic ID of the PLUS protocol
plus.flags.lola | Latency sensitive, when set
plus.flags.roi | Not sensitive to reordering, when set
plus.flags.stop | Stop the association, when set
plus.flags.extended | Extended header follows, when set
plus.cat | Connection/Association token for the PLUS association
plus.psn | Packet Serial Number
plus.pse | Packet Serial Echo
plus.pcftype | Path Communication Function Type
plus.pcflength | Path Communication Function Length
plus.pcfii | Path Communication Function Integrity Indication
plus.pcfvalue | Path Communication Function Value
plus.data | Data of higher layer
