/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.store.pcap.decoder;

import com.google.common.base.Preconditions;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.ACTUAL_LENGTH_OFFSET;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.ARP_PROTOCOL;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.AUTHENTICATION_V6;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.DESTINATION_OPTIONS_V6;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.ENCAPSULATING_SECURITY_V6;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.ETHER_HEADER_LENGTH;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.FRAGMENT_V6;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.HOP_BY_HOP_EXTENSION_V6;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.ICMP_PROTOCOL;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.IP4_DST_OFFSET;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.IP4_SRC_OFFSET;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.IP6_DST_OFFSET;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.IP6_SRC_OFFSET;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.IP_OFFSET;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.MOBILITY_EXTENSION_V6;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.NO_NEXT_HEADER;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.ORIGINAL_LENGTH_OFFSET;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.PACKET_PROTOCOL_OFFSET;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.PCAP_HEADER_SIZE;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.ROUTING_V6;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.TCP_PROTOCOL;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.TIMESTAMP_MICRO_OFFSET;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.TIMESTAMP_OFFSET;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.UDP_HEADER_LENGTH;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.UDP_PROTOCOL;
import static org.apache.drill.exec.store.pcap.decoder.PacketConstants.VER_IHL_OFFSET;

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
  private int pcapOffset;
  private byte[] raw;
  private byte[] packet;

  private int etherOffset;
  private int ipOffset;

  private InetAddress src_ip;
  private InetAddress dst_ip;

  private int src_port;
  private int dst_port;
  private byte[] data;

  private int packetLength;
  private int etherProtocol;
  private int protocol;

  private PacketDecoder decoder;

  public Packet() {
  }

  public Packet(PacketDecoder decoder) {
    this.decoder = decoder;
  }

  @SuppressWarnings("WeakerAccess")
  public boolean readPcap(InputStream in) throws IOException {
    pcapHeader = new byte[PCAP_HEADER_SIZE];
    pcapOffset = 0;
    int n = in.read(pcapHeader);
    if (n < pcapHeader.length) {
      return false;
    }
    int originalLength = decodePcapHeader();

    raw = new byte[originalLength];
    n = in.read(raw);
    if (n < 0) {
      return false;
    }
    etherOffset = 0;

    decodeEtherPacket(raw);
    return true;
  }

  @SuppressWarnings("WeakerAccess")
  public int decodePcap(final byte[] buffer, final int offset) {
    pcapOffset = offset;

    raw = buffer;
    etherOffset = offset + PCAP_HEADER_SIZE;

    pcapHeader = Arrays.copyOfRange(raw, pcapOffset, etherOffset);
    int originalLength = decodePcapHeader();

    packet = Arrays.copyOfRange(raw, etherOffset, packetLength + etherOffset);
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
    if (isIpV4Packet()) {
      Preconditions.checkState(ipVersion() == 4, "Should have seen IP version 4, got %d", ipVersion());

      int n = ipV4HeaderLength();
      Preconditions.checkState(n >= 20 && n < 200, "Invalid header length: ", n);

//        Preconditions.checkState(getShort(raw, ipOffset + 6) == 0, "Don't support IP fragmentation yet");

      protocol = decoder.getByte(raw, ipOffset + 9);
    } else if (isIpV6Packet()) {
      Preconditions.checkState(ipVersion() == 6, "Should have seen IP version 6, got %d", ipVersion());
      //ipVersion = 6;

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
            //noinspection ConstantConditions
            Preconditions.checkState(false, "Can't handle ENCAPSULATING_SECURITY extension");
            break;
          case MOBILITY_EXTENSION_V6:
            //noinspection ConstantConditions
            Preconditions.checkState(false, "Can't handle ENCAPSULATING_SECURITY extension");
            break;
          default:
            protocol = decoder.getByte(raw, ipOffset + headerLength);
            Preconditions.checkState(false, "Unknown V6 extension or protocol: ", nextHeader);
            break;
        }
      }
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

    int srcPortOffset = ETHER_HEADER_LENGTH +
        ipV4HeaderLength() + inTCPHeaderSrcPortOffset;
    this.src_port = convertShort(packet, srcPortOffset);

    int dstPortOffset = ETHER_HEADER_LENGTH +
        ipV4HeaderLength() + inTCPHeaderDstPortOffset;
    this.dst_port = this.convertShort(packet, dstPortOffset);


    int payloadDataStart = ETHER_HEADER_LENGTH +
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

    int srcPortOffset = ETHER_HEADER_LENGTH +
        ipV4HeaderLength() + inUDPHeaderSrcPortOffset;
    this.src_port = this.convertShort(packet, srcPortOffset);

    int dstPortOffset = ETHER_HEADER_LENGTH +
        ipV4HeaderLength() + inUDPHeaderDstPortOffset;
    this.dst_port = this.convertShort(packet, dstPortOffset);

    int payloadDataStart = ETHER_HEADER_LENGTH +
        ipV4HeaderLength() + UDP_HEADER_LENGTH;
    byte[] data = new byte[0];
    if ((packet.length - payloadDataStart) > 0) {
      data = new byte[packet.length - payloadDataStart];
      System.arraycopy(packet, payloadDataStart, data, 0, data.length);
    }
    this.data = data;
  }

  private int getIPHeaderLength(final byte[] packet) {
    return (packet[VER_IHL_OFFSET] & 0xF) * 4;
  }

  private int getTCPHeaderLength(final byte[] packet) {
    final int inTCPHeaderDataOffset = 12;

    int dataOffset = ETHER_HEADER_LENGTH +
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

  public String getPacketType() {
    if (isTcpPacket()) {
      return "TCP";
    } else if (isUdpPacket()) {
      return "UDP";
    } else if (isArpPacket()) {
      return "ARP";
    } else if (isIcmpPacket()) {
      return "ICMP";
    } else {
      return "unknown";
    }
  }

  @SuppressWarnings("WeakerAccess")
  public boolean isIpV4Packet() {
    return etherProtocol == 0x800;
  }

  @SuppressWarnings("WeakerAccess")
  public boolean isIpV6Packet() {
    return etherProtocol == 0x86dd;
  }

  @SuppressWarnings("WeakerAccess")
  public boolean isTcpPacket() {
    return protocol == TCP_PROTOCOL;
  }

  @SuppressWarnings("WeakerAccess")
  public boolean isUdpPacket() {
    return protocol == UDP_PROTOCOL;
  }

  @SuppressWarnings("WeakerAccess")
  public boolean isArpPacket() {
    return protocol == ARP_PROTOCOL;
  }

  @SuppressWarnings("WeakerAccess")
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

  public InetAddress getSrc_ip() {
    return getIPAddress(true);
  }

  public InetAddress getDst_ip() {
    return getIPAddress(false);
  }

  private InetAddress getIPAddress(boolean src) {
    int srcPos;
    byte[] dstIP;
    if (isIpV4Packet()) {
      dstIP = new byte[4];
      srcPos = src ? IP4_SRC_OFFSET : IP4_DST_OFFSET;
    } else if (isIpV6Packet()) {
      dstIP = new byte[16];
      srcPos = src ? IP6_SRC_OFFSET : IP6_DST_OFFSET;
    } else {
      return null;
    }

    System.arraycopy(packet, srcPos, dstIP, 0, dstIP.length);
    try {
      return InetAddress.getByAddress(dstIP);
    } catch (UnknownHostException e) {
      return null;
    }
  }

  public byte[] getData() {
    return data;
  }
}
