package org.apache.drill.exec.store.pcap.decoder;

public final class PacketConstants {

    public static final int PCAP_HEADER_SIZE = 4 * 4;

    public static final int TIMESTAMP_OFFSET = 0;
    public static final int TIMESTAMP_MICRO_OFFSET = 4;
    public static final int ORIGINAL_LENGTH_OFFSET = 8;
    public static final int ACTUAL_LENGTH_OFFSET = 12;

    public static final int PACKET_PROTOCOL_OFFSET = 12;

    public static final byte ARP_PROTOCOL = 0;
    public static final byte ICMP_PROTOCOL = 1;
    public static final byte TCP_PROTOCOL = 6;
    public static final byte UDP_PROTOCOL = 17;

    public static final int HOP_BY_HOP_EXTENSION_V6 = 0;
    public static final int DESTINATION_OPTIONS_V6 = 60;
    public static final int ROUTING_V6 = 43;
    public static final int FRAGMENT_V6 = 44;
    public static final int AUTHENTICATION_V6 = 51;
    public static final int ENCAPSULATING_SECURITY_V6 = 50;
    public static final int MOBILITY_EXTENSION_V6 = 135;
    public static final int NO_NEXT_HEADER = 59;
    public static final int UDP_HEADER_LENGTH = 8;
    public static final int VER_IHL_OFFSET = 14;

    public static final int IP_OFFSET = 14;

    public static final int IP_SRC_OFFSET = 26;
    public static final int IP_DST_OFFSET = 30;

    public static final int etherHeaderLength = 14;
//  public static final int etherTypeOffset = 12;
//  public static final int etherTypeIP = 0x800;
}
