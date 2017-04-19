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

  private int etherOffset;
  private int ipOffset;
  private int ipVersion;

  private int payloadOffset;

  private int src_port;
  private int dst_port;
  private byte[] data;

  private int packetLength;
  private int etherProtocol;
  private int protocol;

  private int getIPHeaderLength(final byte[] packet) {
    return (packet[PacketConstants.VER_IHL_OFFSET] & 0xF) * 4;
  }

  private int getTCPHeaderLength(final byte[] packet) {
    final int inTCPHeaderDataOffset = 12;

    int dataOffset = PacketConstants.ETHER_HEADER_LENGTH + getIPHeaderLength(packet) + inTCPHeaderDataOffset;
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
    return (PacketDecoder.getByte(raw, ipOffset) & 0xf) * 4;
  }

  private int ipVersion() {
    return PacketDecoder.getByte(raw, ipOffset) >>> 4;
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
    return protocol == PacketConstants.TCP_PROTOCOL;
  }

  @SuppressWarnings("WeakerAccess")
  public boolean isUdpPacket() {
    return protocol == PacketConstants.UDP_PROTOCOL;
  }

  @SuppressWarnings("WeakerAccess")
  public boolean isArpPacket() {
    return protocol == PacketConstants.ARP_PROTOCOL;
  }

  @SuppressWarnings("WeakerAccess")
  public boolean isIcmpPacket() {
    return protocol == PacketConstants.ICMP_PROTOCOL;
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
      srcPos = src ? PacketConstants.IP4_SRC_OFFSET : PacketConstants.IP4_DST_OFFSET;
    } else if (isIpV6Packet()) {
      dstIP = new byte[16];
      srcPos = src ? PacketConstants.IP6_SRC_OFFSET : PacketConstants.IP6_DST_OFFSET;
    } else {
      return null;
    }

    System.arraycopy(raw, etherOffset + srcPos, dstIP, 0, dstIP.length);
    try {
      return InetAddress.getByAddress(dstIP);
    } catch (UnknownHostException e) {
      return null;
    }
  }

  @SuppressWarnings("WeakerAccess")
  public boolean readPcap(InputStream in, boolean byteOrder, int maxLength) throws IOException {
    pcapHeader = new byte[PacketConstants.PCAP_HEADER_SIZE];
    pcapOffset = 0;
    int n = in.read(pcapHeader);
    if (n < pcapHeader.length) {
      return false;
    }
    int originalLength = decodePcapHeader(byteOrder, maxLength);

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
  public int decodePcap(final byte[] buffer, final int offset, boolean byteOrder, int maxLength) {
    pcapOffset = offset;

    raw = buffer;
    etherOffset = offset + PacketConstants.PCAP_HEADER_SIZE;

    pcapHeader = Arrays.copyOfRange(raw, pcapOffset, etherOffset);
    int originalLength = decodePcapHeader(byteOrder, maxLength);

    byte[] packet = Arrays.copyOfRange(raw, etherOffset, packetLength + etherOffset);
    decodeEtherPacket(packet);
    return offset + PacketConstants.PCAP_HEADER_SIZE + originalLength;
  }

  private int decodePcapHeader(boolean byteOrder, int maxLength) {
    timestamp = PacketDecoder.getIntFileOrder(byteOrder, pcapHeader, PacketConstants.TIMESTAMP_OFFSET) * 1000L + PacketDecoder.getIntFileOrder(byteOrder, pcapHeader, PacketConstants.TIMESTAMP_MICRO_OFFSET) / 1000L;
    int originalLength = PacketDecoder.getIntFileOrder(byteOrder, pcapHeader, PacketConstants.ORIGINAL_LENGTH_OFFSET);
    Preconditions.checkState(originalLength < maxLength, "Packet too long (%d bytes)", originalLength);
    packetLength = PacketDecoder.getIntFileOrder(byteOrder, pcapHeader, PacketConstants.ACTUAL_LENGTH_OFFSET);
    return originalLength;
  }

  private void decodeEtherPacket(byte[] packet) {
    etherProtocol = PacketDecoder.getShort(packet, PacketConstants.PACKET_PROTOCOL_OFFSET);
    ipOffset = etherOffset + PacketConstants.IP_OFFSET;
    if (isIpV4Packet()) {
      Preconditions.checkState(ipVersion() == 4, "Should have seen IP version 4, got %d", ipVersion());
      ipVersion = 4;

      int n = ipV4HeaderLength();
      Preconditions.checkState(n >= 20 && n < 200, "Invalid header length: ", n);

//        Preconditions.checkState(getShort(raw, ipOffset + 6) == 0, "Don't support IP fragmentation yet");

      protocol = PacketDecoder.getByte(raw, ipOffset + 9);
    } else if (isIpV6Packet()) {
      Preconditions.checkState(ipVersion() == 6, "Should have seen IP version 6, got %d", ipVersion());
      ipVersion = 6;

      int headerLength = 40;
      int nextHeader = raw[ipOffset + 6] & 0xff;
      while (nextHeader != PacketConstants.TCP_PROTOCOL && nextHeader != PacketConstants.UDP_PROTOCOL && nextHeader != PacketConstants.NO_NEXT_HEADER) {
        switch (nextHeader) {
          case PacketConstants.HOP_BY_HOP_EXTENSION_V6:
            nextHeader = PacketDecoder.getByte(raw, ipOffset + headerLength);
            headerLength += (PacketDecoder.getByte(raw, ipOffset + headerLength) + 1) * 8;
            break;
          case PacketConstants.DESTINATION_OPTIONS_V6:
            nextHeader = PacketDecoder.getByte(raw, ipOffset + headerLength);
            headerLength += (PacketDecoder.getByte(raw, ipOffset + headerLength) + 1) * 8;
            break;
          case PacketConstants.ROUTING_V6:
            nextHeader = PacketDecoder.getByte(raw, ipOffset + headerLength);
            headerLength += (PacketDecoder.getByte(raw, ipOffset + headerLength) + 1) * 8;
            break;
          case PacketConstants.FRAGMENT_V6:
            nextHeader = PacketDecoder.getByte(raw, ipOffset + headerLength);
            headerLength += 8;
            break;
          case PacketConstants.AUTHENTICATION_V6:
            break;
          case PacketConstants.ENCAPSULATING_SECURITY_V6:
            //noinspection ConstantConditions
            Preconditions.checkState(false, "Can't handle ENCAPSULATING_SECURITY extension");
            break;
          case PacketConstants.MOBILITY_EXTENSION_V6:
            //noinspection ConstantConditions
            Preconditions.checkState(false, "Can't handle ENCAPSULATING_SECURITY extension");
            break;
          default:
            protocol = PacketDecoder.getByte(raw, ipOffset + headerLength);
            //noinspection ConstantConditions
            Preconditions.checkState(false, "Unknown V6 extension or protocol: ", nextHeader);
            break;
        }
      }
      if (nextHeader != PacketConstants.NO_NEXT_HEADER) {
        payloadOffset = ipOffset + headerLength;
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

    int srcPortOffset = PacketConstants.ETHER_HEADER_LENGTH +
        ipV4HeaderLength() + inTCPHeaderSrcPortOffset;
    this.src_port = convertShort(packet, srcPortOffset);

    int dstPortOffset = PacketConstants.ETHER_HEADER_LENGTH +
        ipV4HeaderLength() + inTCPHeaderDstPortOffset;
    this.dst_port = this.convertShort(packet, dstPortOffset);


    int payloadDataStart = PacketConstants.ETHER_HEADER_LENGTH +
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

    int srcPortOffset = PacketConstants.ETHER_HEADER_LENGTH +
        ipV4HeaderLength() + inUDPHeaderSrcPortOffset;
    this.src_port = this.convertShort(packet, srcPortOffset);

    int dstPortOffset = PacketConstants.ETHER_HEADER_LENGTH +
        ipV4HeaderLength() + inUDPHeaderDstPortOffset;
    this.dst_port = this.convertShort(packet, dstPortOffset);

    int payloadDataStart = PacketConstants.ETHER_HEADER_LENGTH +
        ipV4HeaderLength() + PacketConstants.UDP_HEADER_LENGTH;
    byte[] data = new byte[0];
    if ((packet.length - payloadDataStart) > 0) {
      data = new byte[packet.length - payloadDataStart];
      System.arraycopy(packet, payloadDataStart, data, 0, data.length);
    }
    this.data = data;
  }

  public String getEthernetSource() {
    byte[] r = new byte[6];
    System.arraycopy(raw, etherOffset + PacketConstants.ETHER_SRC_OFFSET, r, 0, 6);
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < r.length; i++) {
      sb.append(String.format("%02X%s", r[i], (i < r.length - 1) ? ":" : ""));
    }
    return sb.toString();
  }

  public String getEthernetDestination() {
    byte[] r = new byte[6];
    System.arraycopy(raw, etherOffset + PacketConstants.ETHER_DST_OFFSET, r, 0, 6);
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < r.length; i++) {
      sb.append(String.format("%02X%s", r[i], (i < r.length - 1) ? ":" : ""));
    }
    return sb.toString();
  }

  public byte[] getData() {
    return data;
  }
}
