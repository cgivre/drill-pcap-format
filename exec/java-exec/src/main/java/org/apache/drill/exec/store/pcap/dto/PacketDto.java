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
package org.apache.drill.exec.store.pcap.dto;

import edu.gatech.sjpcap.TCPPacket;
import edu.gatech.sjpcap.UDPPacket;

import java.util.Arrays;

public class PacketDto {

  private final String packetName;
  private final long timestamp;
  private final IpDto ip;
  private final PortDto port;
  private final byte[] data;

  public PacketDto(TCPPacket packet) {
    this.packetName = "TCP";
    this.timestamp = packet.timestamp;
    this.ip = new IpDto(packet.dst_ip, packet.src_ip);
    this.port = new PortDto(packet.dst_port, packet.src_port);
    this.data = packet.data;
  }

  public PacketDto(UDPPacket packet) {
    this.packetName = "UDP";
    this.timestamp = packet.timestamp;
    this.ip = new IpDto(packet.dst_ip, packet.src_ip);
    this.port = new PortDto(packet.dst_port, packet.src_port);
    this.data = packet.data;
  }

  public String getPacketName() {
    return packetName;
  }

  public long getTimestamp() {
    return timestamp;
  }

  public IpDto getIp() {
    return ip;
  }

  public PortDto getPort() {
    return port;
  }

  public String getData() {
    return Arrays.toString(data);
  }
}
