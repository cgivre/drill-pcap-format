/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.store.pcap;


public class PcapHelperFunctions {

        private static final String[] protocol_abbreviatons = {"HOPOPT", "ICMP", "IGMP", "GGP", "IP-in-IP", "ST", "TCP", "CBT", "EGP", "IGP", "BBN-RCC-MON", "NVP-II", "PUP", "ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "MUX", "DCN-MEAS", "HMP", "PRM", "XNS-IDP", "TRUNK-1", "TRUNK-2", "LEAF-1", "LEAF-2", "RDP", "IRTP", "ISO-TP4", "NETBLT", "MFE-NSP", "MERIT-INP", "DCCP", "3PC", "IDPR", "XTP", "DDP", "IDPR-CMTP", "TP++", "IL", "IPv6", "SDRP", "IPv6-Route", "IPv6-Frag", "IDRP", "RSVP", "GRE", "MHRP", "BNA", "ESP", "AH", "I-NLSP", "SWIPE", "NARP", "MOBILE", "TLSP", "SKIP", "IPv6-ICMP", "IPv6-NoNxt", "IPv6-Opts", "", "CFTP", "", "SAT-EXPAK", "KRYPTOLAN", "RVD", "IPPC", "", "SAT-MON", "VISA", "IPCU", "CPNX", "CPHB", "WSN", "PVP", "BR-SAT-MON", "SUN-ND", "WB-MON", "WB-EXPAK", "ISO-IP", "VMTP", "SECURE-VMTP", "VINES", "TTP", "IPTM", "NSFNET-IGP", "DGP", "TCF", "EIGRP", "OSPF", "Sprite-RPC", "LARP", "MTP", "AX.25", "OS", "MICP", "SCC-SP", "ETHERIP", "ENCAP", "", "GMTP", "IFMP", "PNNI", "PIM", "ARIS", "SCPS", "QNX", "A/N", "IPComp", "SNP", "Compaq-Peer", "IPX-in-IP", "VRRP", "PGM", "", "L2TP", "DDX", "IATP", "STP", "SRP", "UTI", "SMP", "SM", "PTP", "IS-IS over IPv4", "FIRE", "CRTP", "CRUDP", "SSCOPMCE", "", "IPLT", "SPS", "PIPE", "SCTP", "FC", "RSVP-E2E-IGNORE", "Mobility Header", "UDPLite", "MPLS-in-IP", "manet", "HIP", "Shim6", "WESP", "ROHC"};

        public static final String[] ip_protocol_description = {"IPv6 Hop-by-Hop Option", "Internet Control Message Protocol", "Internet Group Management Protocol", "Gateway-to-Gateway Protocol", "IP in IP (encapsulation)", "Internet Stream Protocol", "Transmission Control Protocol", "Core-based trees", "Exterior Gateway Protocol", "Interior Gateway Protocol (any private interior gateway (used by Cisco for their IGRP))", "BBN RCC Monitoring", "Network Voice Protocol", "Xerox PUP", "ARGUS", "EMCON", "Cross Net Debugger", "Chaos", "User Datagram Protocol", "Multiplexing", "DCN Measurement Subsystems", "Host Monitoring Protocol", "Packet Radio Measurement", "XEROX NS IDP", "Trunk-1", "Trunk-2", "Leaf-1", "Leaf-2", "Reliable Datagram Protocol", "Internet Reliable Transaction Protocol", "ISO Transport Protocol Class 4", "Bulk Data Transfer Protocol", "MFE Network Services Protocol", "MERIT Internodal Protocol", "Datagram Congestion Control Protocol", "Third Party Connect Protocol", "Inter-Domain Policy Routing Protocol", "Xpress Transport Protocol", "Datagram Delivery Protocol", "IDPR Control Message Transport Protocol", "TP++ Transport Protocol", "IL Transport Protocol", "IPv6 Encapsulation", "Source Demand Routing Protocol", "Routing Header for IPv6", "Fragment Header for IPv6", "Inter-Domain Routing Protocol", "Resource Reservation Protocol", "Generic Routing Encapsulation", "Mobile Host Routing Protocol", "BNA", "Encapsulating Security Payload", "Authentication Header", "Integrated Net Layer Security Protocol", "SwIPe", "NBMA Address Resolution Protocol", "IP Mobility (Min Encap)", "Transport Layer Security Protocol (using Kryptonet key management)", "Simple Key-Management for Internet Protocol", "ICMP for IPv6", "No Next Header for IPv6", "Destination Options for IPv6", "Any host internal protocol", "CFTP", "Any local network", "SATNET and Backroom EXPAK", "Kryptolan", "MIT Remote Virtual Disk Protocol", "Internet Pluribus Packet Core", "Any distributed file system", "SATNET Monitoring", "VISA Protocol", "Internet Packet Core Utility", "Computer Protocol Network Executive", "Computer Protocol Heart Beat", "Wang Span Network", "Packet Video Protocol", "Backroom SATNET Monitoring", "SUN ND PROTOCOL-Temporary", "WIDEBAND Monitoring", "WIDEBAND EXPAK", "International Organization for Standardization Internet Protocol", "Versatile Message Transaction Protocol", "Secure Versatile Message Transaction Protocol", "VINES", "TTP", "Internet Protocol Traffic Manager", "NSFNET-IGP", "Dissimilar Gateway Protocol", "TCF", "EIGRP", "Open Shortest Path First", "Sprite RPC Protocol", "Locus Address Resolution Protocol", "Multicast Transport Protocol", "AX.25", "KA9Q NOS compatible IP over IP tunneling", "Mobile Internetworking Control Protocol", "Semaphore Communications Sec. Pro", "Ethernet-within-IP Encapsulation", "Encapsulation Header", "Any private encryption scheme", "GMTP", "Ipsilon Flow Management Protocol", "PNNI over IP", "Protocol Independent Multicast", "IBM's ARIS (Aggregate Route IP Switching) Protocol", "SCPS (Space Communications Protocol Standards)", "QNX", "Active Networks", "IP Payload Compression Protocol", "Sitara Networks Protocol", "Compaq Peer Protocol", "IPX in IP", "Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned)", "PGM Reliable Transport Protocol", "Any 0-hop protocol", "Layer Two Tunneling Protocol Version 3", "D-II Data Exchange (DDX)", "Interactive Agent Transfer Protocol", "Schedule Transfer Protocol", "SpectraLink Radio Protocol", "Universal Transport Interface Protocol", "Simple Message Protocol", "Simple Multicast Protocol", "Performance Transparency Protocol", "Intermediate System to Intermediate System (IS-IS) Protocol over IPv4", "Flexible Intra-AS Routing Environment", "Combat Radio Transport Protocol", "Combat Radio User Datagram", "Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment", "", "Secure Packet Shield", "Private IP Encapsulation within IP", "Stream Control Transmission Protocol", "Fibre Channel", "Reservation Protocol (RSVP) End-to-End Ignore", "Mobility Extension Header for IPv6", "Lightweight User Datagram Protocol", "Multiprotocol Label Switching Encapsulated in IP", "MANET Protocols", "Host Identity Protocol", "Site Multihoming by IPv6 Intermediation", "Wrapped Encapsulating Security Payload", "Robust Header Compression"};


    public static String getProtocolName(int p) {
        if (p > 142) {
            return "UNASSIGNED";
        } else {
            return protocol_abbreviatons[p];
        }
    }

    public static String getProtocolDescription(int p) {
        if (p > 142) {
            return "UNASSIGNED";
        } else {
            return ip_protocol_description[p];
        }
    }

}
