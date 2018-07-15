# Meadow
IPREF&#8482; is an IP addressing system where hosts are referred to by a combination of an IP address and a reference, hence ipref. It is used for communication between private networks. The IP portion of an IPREF address is usually an address of one of the gateways to a local network. The reference is an opaque unsigned integer assigned by that local network. References have no meaning beyond the local network they were assigned in. A local network _address mapper_ makes use of them to produce a valid local IP address.

IPREF is for local networks wishing to exchange information with other local networks. There is no intention to support communication between local networks and public Internet using IPREF. However, one may notice that most all services appearing on public Internet are actually hosted on local networks and then made public via traditional Network Address Translation (NAT). IPREF allows to reach those same services on their local, private networks without NAT. It works with IPv4 and IPv6, it is also possible to mix them. IPREF is a better Internet.

Only gateways need to implement IPREF.  Hosts on the attached local networks are not aware of IPREF. There is no need to modify them in any way.

IPREF can be implemented in many different ways. This sample implementation, code named "meadow", uses random assignment of references and encoded local addresses. It integrates _address mapper_ with IPREF _forwarder_. Such arrangement is suitable for local networks with single gateways.

Meadow can be used to test IPREF and to develop other services based on IPREF.

# Block diagram

Major components of the meadow implementation are shown in the diagram below. Blocks in the area between the dash lines are part of the meadow executable. For more realistic operations, DNS support is required. IPREF needs an IPRE aware resolver and a local dynamic DNS server. The resolver and the local DNS server must inform the _mapper_ of all IPREF addresses used by hosts on the local network.

    ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━

                           ┏━━━━━━━━━━━━━━━━━━━━━━━━━┓
                           ┃                         ┃
                           ┃  ╭───────────────────╮  ┃
                           ┃  │ tun   ─╴▷╶─   udp │  ┃
                ipref ifc  ┃  └───────────────────┘  ┃  udp tunnel
                        ───┨  ╭───────────────────╮  ┠───
                           ┃  │ tun   ─╴◁╶─   udp │  ┃
                           ┃  └───────────────────┘  ┃
                           ┃                         ┃
                           ┃         ipref forwarder ┃
                           ┗━━━━━━━━━━━┯━━━━━━━━━━━━━┛
                                       │
                     ┏━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━┓
                     ┃                                     ┃
                     ┃   ┌───────────┐       ╔═════════╗   ┃
                     ┃   │   access  │ ─╴▷╶─ ║ address ║   ┃
                     ┃   │ functions │ ─╴◁╶─ ║ records ║   ┃
                     ┃   └───────────┘       ╚═════════╝   ┃
                     ┃                                     ┃
                     ┃                      address mapper ┃
                     ┗━━━━┯━━━━━━━━━━━━┯━━━━━━━━━━━━━━┯━━━━┛
                          │            │              │
                    ╭─────┴────╮   ╭───┴────╮   ╭─────┴──────╮
                    │ resolver │   │ expire │   │ dns AA rec │
                    │  agent   │   │ timer  │   │  watcher   │
                    └─────┬────┘   └────────┘   └─────┬──────┘
                          │                           │              MEADOW
     ━ ━ ━ ━ ━ ━ ━ ━ ━ ━╺━┿━╸━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━╺━┿━╸━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━
                          │                           │
                          │                       ╔═══╧════╗
                          │                       ║ DNS RR ║
                          │                       ╚═══╤════╝
     local resolver ╭─────┴────╮                 ╭────┴──────╮      advertise
              ──────┤ resolver ├──────┬──────────┤ local dns ├──    AA records
                    └──────────┘      │          └───────────┘
                                      │                          ╭────────────╮
                                      └──────────────────────────┤ public dns │
                                                                 └──────┬─────┘
                                                                    ╔═══╧════╗
                                                                    ║ DNS RR ║
                                                                    ╚════════╝
### IPREF forwarder

IPREF forwarder consists of two threads. One thread receives packet from the tun interface, maps addresses to IPREF, and sends packets to remote gateways via udp tunnel. The other thread operates in the opposite direction. It receives packets from udp tunnel, decodes/encodes addresses from IPREF, and sends packets to the tun interface.

### Address mapper
Address mapper manages mapping between local addresses and their IPREF equivalents. It allocates references and _encoding addresses_. An encoding address is a standard IP address that is presented to local hosts in lieu of an external IPREF address which local hosts would not understand.  Address mapper allocates IPREF addresses for local hosts. It takes into account all IPREF addresses advertised by local network and all IPREF addresses resolved on behalf of local networks' hosts. That information is presented to the _forwarder_ for proper address coding and decoding.

### Resolver
IPREF, similarly to standard IP, does not require DNS for its operations but name mapping service is immensely useful making it a required component of any practical networking system. IPREF requires a resolver that is aware of the _address mapper_. The resolver must inform address mapper of all IPREF DNS queries issued by hosts on the local networks. It also must negotiate allocation of _references_ and _encoding addresses_ with the mapper.

### Local DNS server
Local DNS server is optional. It is used only if the local network wishes to advertise some of its hosts for access via IPREF. In those cases, _address mapper_ must be informed of all advertised hosts. The DNS server does not need to be modified in any special way but it must provide means for the mapper to learn all advertised local hosts.
