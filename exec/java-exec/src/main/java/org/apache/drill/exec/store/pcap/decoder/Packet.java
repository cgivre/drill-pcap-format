package org.apache.drill.exec.store.pcap.decoder;

import com.google.common.base.Preconditions;
import org.apache.drill.exec.store.pcap.dto.IpDto;

import java.net.InetAddress;
import java.util.Arrays;

import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.*;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.ICMP_PROTOCOL;

public class Packet {
    // pcap header
    //        typedef struct pcaprec_hdr_s {
    //            guint32 ts_sec;         /* timestamp seconds */
    //            guint32 ts_usec;        /* timestamp microseconds */
    //            guint32 incl_len;       /* number of octets of packet saved in file */
    //            guint32 orig_len;       /* actual length of packet */
    //        } pcaprec_hdr_t;

    private long timestamp;

    private byte[] pcapHeader;
    private byte[] raw;

    private int etherOffset;
    private int ipOffset;

    private org.apache.drill.exec.store.pcap.dto.IpDto IpDto;

    private int src_port;
    private int dst_port;
    private byte[] data;

    private int packetLength;
    private int etherProtocol;
    private int protocol;

    private PacketDecoder decoder;

    public Packet(PacketDecoder decoder) {
        this.decoder = decoder;
    }

    public int decodePcap(final byte[] buffer, final int offset) {
        int pcapOffset = offset;

        raw = buffer;
        etherOffset = offset + PCAP_HEADER_SIZE;

        pcapHeader = Arrays.copyOfRange(raw, pcapOffset, etherOffset);
        int originalLength = decodePcapHeader();

        byte[] packet = Arrays.copyOfRange(raw, etherOffset, packetLength + etherOffset);
        decodeEtherPacket(packet);
        return offset + PCAP_HEADER_SIZE + originalLength;
    }

    private int decodePcapHeader() {
        timestamp = decoder.getIntFileOrder(pcapHeader, TIMESTAMP_OFFSET) * 1000L + decoder.getIntFileOrder(pcapHeader, TIMESTAMP_MICRO_OFFSET) / 1000L;
        int originalLength = decoder.getIntFileOrder(pcapHeader, ORIGINAL_LENGTH_OFFSET);
        Preconditions.checkState(originalLength < decoder.getMaxLength(), "Packet too long (%d bytes)", originalLength);
        packetLength = decoder.getIntFileOrder(pcapHeader, ACTUAL_LENGTH_OFFSET);
        return originalLength;
    }

    private void decodeEtherPacket(byte[] packet) {
        etherProtocol = decoder.getShort(packet, PACKET_PROTOCOL_OFFSET);
        ipOffset = etherOffset + IP_OFFSET;
        int ipVersion;
        if (isIpV4Packet()) {
            Preconditions.checkState(ipVersion() == 4, "Should have seen IP version 4, got %d", ipVersion());
            ipVersion = 4;

            int n = ipV4HeaderLength();
            Preconditions.checkState(n >= 20 && n < 200, "Invalid header length: ", n);

//        Preconditions.checkState(getShort(raw, ipOffset + 6) == 0, "Don't support IP fragmentation yet");

            protocol = decoder.getByte(raw, ipOffset + 9);
            IpDto = getIPFromPacket(packet);
        } else if (isIpV6Packet()) {
            Preconditions.checkState(ipVersion() == 6, "Should have seen IP version 6, got %d", ipVersion());
            ipVersion = 6;

            int headerLength = 40;
            int nextHeader = raw[ipOffset + 6] & 0xff;
            while (nextHeader != TCP_PROTOCOL && nextHeader != UDP_PROTOCOL && nextHeader != NO_NEXT_HEADER) {
                switch (nextHeader) {
                    case HOP_BY_HOP_EXTENSION_V6:
                        nextHeader = decoder.getByte(raw, ipOffset + headerLength);
                        headerLength += (decoder.getByte(raw, ipOffset + headerLength) + 1) * 8;
                        break;
                    case DESTINATION_OPTIONS_V6:
                        nextHeader = decoder.getByte(raw, ipOffset + headerLength);
                        headerLength += (decoder.getByte(raw, ipOffset + headerLength) + 1) * 8;
                        break;
                    case ROUTING_V6:
                        nextHeader = decoder.getByte(raw, ipOffset + headerLength);
                        headerLength += (decoder.getByte(raw, ipOffset + headerLength) + 1) * 8;
                        break;
                    case FRAGMENT_V6:
                        nextHeader = decoder.getByte(raw, ipOffset + headerLength);
                        headerLength += 8;
                        break;
                    case AUTHENTICATION_V6:
                        break;
                    case ENCAPSULATING_SECURITY_V6:
                        Preconditions.checkState(false, "Can't handle ENCAPSULATING_SECURITY extension");
                        break;
                    case MOBILITY_EXTENSION_V6:
                        Preconditions.checkState(false, "Can't handle ENCAPSULATING_SECURITY extension");
                        break;
                    default:
                        protocol = decoder.getByte(raw, ipOffset + headerLength);
                        Preconditions.checkState(false, "Unknown V6 extension or protocol: ", nextHeader);
                        break;
                }
            }
            if (nextHeader != NO_NEXT_HEADER) {
                int payloadOffset = ipOffset + headerLength;
            }
            IpDto = getIPFromPacket(packet);
            protocol = nextHeader;
        }
        if (isTcpPacket()) {
            buildTCPPacket(packet);
        } else if (isUdpPacket()) {
            buildUDPPacket(packet);
        }
    }

    private void buildTCPPacket(final byte[] packet) {
        final int inTCPHeaderSrcPortOffset = 0;
        final int inTCPHeaderDstPortOffset = 2;

        int srcPortOffset = etherHeaderLength +
                ipV4HeaderLength() + inTCPHeaderSrcPortOffset;
        this.src_port = convertShort(packet, srcPortOffset);

        int dstPortOffset = etherHeaderLength +
                ipV4HeaderLength() + inTCPHeaderDstPortOffset;
        this.dst_port = this.convertShort(packet, dstPortOffset);


        int payloadDataStart = etherHeaderLength +
                getIPHeaderLength(packet) + this.getTCPHeaderLength(packet);
        byte[] data = new byte[0];
        if ((packet.length - payloadDataStart) > 0) {
            data = new byte[packet.length - payloadDataStart];
            System.arraycopy(packet, payloadDataStart, data, 0, data.length);
        }
        this.data = data;
    }

    private void buildUDPPacket(final byte[] packet) {
        final int inUDPHeaderSrcPortOffset = 0;
        final int inUDPHeaderDstPortOffset = 2;

        int srcPortOffset = etherHeaderLength +
                ipV4HeaderLength() + inUDPHeaderSrcPortOffset;
        this.src_port = this.convertShort(packet, srcPortOffset);

        int dstPortOffset = etherHeaderLength +
                ipV4HeaderLength() + inUDPHeaderDstPortOffset;
        this.dst_port = this.convertShort(packet, dstPortOffset);

        int payloadDataStart = etherHeaderLength +
                ipV4HeaderLength() + UDP_HEADER_LENGTH;
        byte[] data = new byte[0];
        if ((packet.length - payloadDataStart) > 0) {
            data = new byte[packet.length - payloadDataStart];
            System.arraycopy(packet, payloadDataStart, data, 0, data.length);
        }
        this.data = data;
    }

    private IpDto getIPFromPacket(final byte[] packet) {
        InetAddress src_ip;
        InetAddress dst_ip;
        byte[] srcIP = new byte[4];
        System.arraycopy(packet, IP_SRC_OFFSET,
                srcIP, 0, srcIP.length);
        try {
            src_ip = InetAddress.getByAddress(srcIP);
        } catch (Exception e) {
            throw new RuntimeException("Source IP in packet is broke");
        }

        byte[] dstIP = new byte[4];
        System.arraycopy(packet, IP_DST_OFFSET,
                dstIP, 0, dstIP.length);
        try {
            dst_ip = InetAddress.getByAddress(dstIP);
        } catch (Exception e) {
            throw new RuntimeException("Destination IP in packet is broke");
        }
        return new IpDto(src_ip, dst_ip);
    }

    private int getIPHeaderLength(final byte[] packet) {
        return (packet[VER_IHL_OFFSET] & 0xF) * 4;
    }

    private int getTCPHeaderLength(final byte[] packet) {
        final int inTCPHeaderDataOffset = 12;

        int dataOffset = etherHeaderLength +
                getIPHeaderLength(packet) + inTCPHeaderDataOffset;
        return ((packet[dataOffset] >> 4) & 0xF) * 4;
    }

    private int convertShort(final byte[] data) {
        return ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
    }

    private int convertShort(final byte[] data, int offset) {
        byte[] target = new byte[2];
        System.arraycopy(data, offset, target, 0, target.length);
        return this.convertShort(target);
    }

    private int ipV4HeaderLength() {
        return (decoder.getByte(raw, ipOffset) & 0xf) * 4;
    }

    private int ipVersion() {
        return decoder.getByte(raw, ipOffset) >>> 4;
    }

    public boolean isIpV4Packet() {
        return etherProtocol == 0x800;
    }

    public boolean isIpV6Packet() {
        return etherProtocol == 0x86dd;
    }

    public boolean isTcpPacket() {
        return protocol == TCP_PROTOCOL;
    }

    public boolean isUdpPacket() {
        return protocol == UDP_PROTOCOL;
    }

    public boolean isArpPacket() {
        return protocol == ARP_PROTOCOL;
    }

    public boolean isIcmpPacket() {
        return protocol == ICMP_PROTOCOL;
    }

    public int getPacketLength() {
        return packetLength;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public int getSrc_port() {
        return src_port;
    }

    public int getDst_port() {
        return dst_port;
    }

    public byte[] getData() {
        return data;
    }

    public IpDto getIpDto() {
        return IpDto;
    }
}
