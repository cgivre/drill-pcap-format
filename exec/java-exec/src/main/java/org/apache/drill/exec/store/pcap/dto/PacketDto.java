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

import org.apache.drill.exec.store.pcap.decoder.PacketDecoder.Packet;

public class PacketDto {

  private final String packetName;
  private final long timestamp;
  private final IpDto ip;
  private final int packetLength;
  private final int src_port;
  private final int dst_port;
  private final byte[] data;
  private final int network;

  public PacketDto(String packetName, int networkType, Packet packet) {
    this.packetName = packetName;
    this.network = networkType;
    this.timestamp = packet.getTimestamp();
    this.ip = packet.getIpDto();
    this.packetLength = packet.getPacketLength();
    this.src_port = packet.getSrc_port();
    this.dst_port = packet.getDst_port();
    this.data = packet.getData();
  }

  public String getPacketName() {
    return packetName;
  }

  public int getNetwork() {
    return network;
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

  public IpDto getIp() {
    return ip;
  }

  public int getPacketLength() {
    return packetLength;
  }

  public byte[] getData() {
    return data;
  }
}