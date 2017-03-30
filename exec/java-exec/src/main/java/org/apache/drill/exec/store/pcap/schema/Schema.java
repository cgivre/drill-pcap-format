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
package org.apache.drill.exec.store.pcap.schema;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Schema {

  private final List<ColumnDTO> columns = new ArrayList<>();

  public Schema() {
    setupStructure();
  }

  private void setupStructure() {
    columns.add(new ColumnDTO("Type", PcapTypes.STRING));
    columns.add(new ColumnDTO("Timestamp", PcapTypes.TIMESTAMP));
    columns.add(new ColumnDTO("dst_ip", PcapTypes.STRING));
    columns.add(new ColumnDTO("src_ip", PcapTypes.STRING));
    columns.add(new ColumnDTO("dst_port", PcapTypes.INTEGER));
    columns.add(new ColumnDTO("src_port", PcapTypes.INTEGER));
    columns.add(new ColumnDTO("Data", PcapTypes.STRING));
  }

  /**
   * Return list with all columns names and its types
   *
   * @return List<ColumnDTO>
   */
  public List<ColumnDTO> getColumns() {
    return Collections.unmodifiableList(columns);
  }

  public ColumnDTO getColumnByIndex(int i) {
    return columns.get(i);
  }

  public int getNumberOfColumns() {
    return columns.size();
  }
}
