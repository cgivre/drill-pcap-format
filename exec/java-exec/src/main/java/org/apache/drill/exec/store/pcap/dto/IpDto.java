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

import java.net.InetAddress;

public class IpDto {

  private final InetAddress src_ip;
  private final InetAddress dst_ip;


  public IpDto(InetAddress src_ip, InetAddress dst_ip) {
    this.src_ip = src_ip;
    this.dst_ip = dst_ip;
  }

  public InetAddress getSrc_ip() {
    return src_ip;
  }

  public InetAddress getDst_ip() {
    return dst_ip;
  }
}