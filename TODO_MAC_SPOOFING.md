# TODO: MAC override behavior

Goal: allow arpsponge to emit ARP replies with an override MAC while preserving
normal traffic from the interface's real hardware MAC.

Background
- Some NICs/drivers/switches treat source-MAC spoofing as a port-security event.
- When arpsponge emits ARP with a different source MAC, normal traffic may be
  disrupted or blocked at L2.

Known constraints of the current experimental `--mac` flag
- The override is used as the engine's single `myMAC` value, but capture still
  arrives through the interface's real hardware MAC. Consequently, the
  destination-MAC check does not match frames addressed to the real MAC, so
  `--arp-update-method` does not fire as it does without an override.
- The self-filter recognizes injected frames sourced from the override MAC,
  but does not recognize frames the host sends from its real hardware MAC.
  Those frames can therefore be processed as ordinary input.
- These are limitations of the current single-MAC capture/injection model;
  they are separate from the switch/NIC port-security and normal-traffic risks
  above. The dedicated-interface designs below are intended to address them.

Ideas to explore
- Linux macvlan/ipvlan: create a secondary interface with the override MAC and
  bind arpsponge to that interface (keep base interface for normal traffic).
- VLAN sub-interface with distinct MAC where supported.
- Network namespace/container with veth pair to isolate the spoofed MAC.
- Document OS/driver combinations that allow source-MAC spoofing without impact.

Implementation sketch
- Add optional flag (e.g., --mac-iface) to select a dedicated interface for
  ARP reply injection while capturing on the primary interface.
- Decide how to choose capture vs. send interfaces in the platform layer.
- Update docs with safe recipes per platform.

Open questions
- Should arpsponge support split capture/send interfaces?
- How to keep control socket/path naming if a secondary interface is used?
- How to select/update the MAC for only ARP reply packets while preserving
  original L2 for other traffic?
