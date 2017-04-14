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

import java.net.InetAddress;

public class PacketDto {

  private final String packetName;
  private final long timestamp;
  private final int packetLength;
  private final int src_port;
  private final int dst_port;
  private final InetAddress src_ip;
  private final InetAddress dst_ip;
  private final byte[] data;
  private final int network;

  public PacketDto(String packetName, int networkType, Packet packet) {
    this.packetName = packetName;
    this.network = networkType;
    this.timestamp = packet.getTimestamp();
    this.packetLength = packet.getPacketLength();
    this.src_ip = packet.getSrc_ip();
    this.src_port = packet.getSrc_port();
    this.dst_ip = packet.getDst_ip();
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

  public InetAddress getSrc_ip() {
    return src_ip;
  }

  public int getDst_port() {
    return dst_port;
  }

  public InetAddress getDst_ip() {
    return dst_ip;
  }

  public int getPacketLength() {
    return packetLength;
  }

  public byte[] getData() {
    return data;
  }
}
