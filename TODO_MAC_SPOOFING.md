# TODO: MAC override behavior

Goal: allow arpsponge to emit ARP replies with an override MAC while preserving
normal traffic from the interface's real hardware MAC.

Background
- Some NICs/drivers/switches treat source-MAC spoofing as a port-security event.
- When arpsponge emits ARP with a different source MAC, normal traffic may be
  disrupted or blocked at L2.

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
