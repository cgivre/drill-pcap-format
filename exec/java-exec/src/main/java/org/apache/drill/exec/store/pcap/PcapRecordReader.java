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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import edu.gatech.sjpcap.Packet;
import edu.gatech.sjpcap.PcapParser;
import edu.gatech.sjpcap.TCPPacket;
import edu.gatech.sjpcap.UDPPacket;
import org.apache.drill.common.exceptions.ExecutionSetupException;
import org.apache.drill.common.expression.SchemaPath;
import org.apache.drill.common.types.TypeProtos;
import org.apache.drill.common.types.TypeProtos.MinorType;
import org.apache.drill.common.types.Types;
import org.apache.drill.exec.exception.SchemaChangeException;
import org.apache.drill.exec.expr.TypeHelper;
import org.apache.drill.exec.ops.OperatorContext;
import org.apache.drill.exec.physical.impl.OutputMutator;
import org.apache.drill.exec.record.MaterializedField;
import org.apache.drill.exec.store.AbstractRecordReader;
import org.apache.drill.exec.store.pcap.dto.IpDto;
import org.apache.drill.exec.store.pcap.dto.PortDto;
import org.apache.drill.exec.store.pcap.schema.ColumnDTO;
import org.apache.drill.exec.store.pcap.schema.PcapTypes;
import org.apache.drill.exec.store.pcap.schema.Schema;
import org.apache.drill.exec.vector.NullableIntVector;
import org.apache.drill.exec.vector.NullableTimeStampVector;
import org.apache.drill.exec.vector.NullableVarCharVector;
import org.apache.drill.exec.vector.ValueVector;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class PcapRecordReader extends AbstractRecordReader {

  private OutputMutator output;
  private OperatorContext context;

  private final PcapParser parser;
  private ImmutableList<ProjectedColumnInfo> projectedCols;

  private static final Map<PcapTypes, TypeProtos.MinorType> TYPES;

  private static class ProjectedColumnInfo {
    ValueVector vv;
    ColumnDTO pcapColumn;
  }

  static {
    TYPES = ImmutableMap.<PcapTypes, TypeProtos.MinorType>builder()
        .put(PcapTypes.STRING, MinorType.VARCHAR)
        .put(PcapTypes.INTEGER, MinorType.INT)
        .put(PcapTypes.TIMESTAMP, MinorType.TIMESTAMP)
        .build();
  }

  public PcapRecordReader(final String inputPath,
                          final List<SchemaPath> projectedColumns) {
    this.parser = new PcapParser();
    parser.openFile(getPathToFile(inputPath));
    setColumns(projectedColumns);
  }

  @Override
  public void setup(final OperatorContext context, final OutputMutator output) throws ExecutionSetupException {
    this.output = output;
    this.context = context;
  }

  @Override
  public int next() {
    projectedCols = getProjectedColsIfItNull();
    return parsePcapFilesAndPutItToTable();
  }

  @Override
  public void close() throws Exception {
  }

  private ImmutableList<ProjectedColumnInfo> getProjectedColsIfItNull() {
    return projectedCols != null ? projectedCols : initCols(new Schema());
  }

  // TODO: tricky decision, refactor
  private String getPathToFile(final String path) {
    return path.substring(5);
  }

  private ImmutableList<ProjectedColumnInfo> initCols(final Schema schema) {
    ImmutableList.Builder<ProjectedColumnInfo> pciBuilder = ImmutableList.builder();
    ColumnDTO column;

    for (int i = 0; i < schema.getNumberOfColumns(); i++) {
      column = schema.getColumnByIndex(i);

      final String name = column.getColumnName();
      final PcapTypes type = column.getColumnType();
      TypeProtos.MinorType minorType = TYPES.get(type);

      ProjectedColumnInfo pci = getProjectedColumnInfo(column, name, minorType);
      pciBuilder.add(pci);
    }
    return pciBuilder.build();
  }

  private ProjectedColumnInfo getProjectedColumnInfo(final ColumnDTO column,
                                                     final String name,
                                                     final MinorType minorType) {
    TypeProtos.MajorType majorType = getMajorType(minorType);

    MaterializedField field =
        MaterializedField.create(name, majorType);

    ValueVector vector =
        getValueVector(minorType, majorType, field);

    return getProjectedColumnInfo(column, vector);
  }

  private ProjectedColumnInfo getProjectedColumnInfo(final ColumnDTO column, final ValueVector vector) {
    ProjectedColumnInfo pci = new ProjectedColumnInfo();
    pci.vv = vector;
    pci.pcapColumn = column;
    return pci;
  }

  private TypeProtos.MajorType getMajorType(final TypeProtos.MinorType minorType) {
    return Types.optional(minorType);
  }

  private ValueVector getValueVector(final TypeProtos.MinorType minorType,
                                     final TypeProtos.MajorType majorType,
                                     final MaterializedField field) {
    try {

      final Class<? extends ValueVector> clazz = TypeHelper.getValueVectorClass(
          minorType, majorType.getMode());
      ValueVector vector = output.addField(field, clazz);
      vector.allocateNew();
      return vector;

    } catch (SchemaChangeException sce) {
      throw new NullPointerException("The addition of this field is incompatible with this OutputMutator's capabilities");
    }
  }

  private int parsePcapFilesAndPutItToTable() {
    Packet packet = parser.getPacket();
    while (packet != Packet.EOF) {
      if (packet instanceof TCPPacket) {
        TCPPacket tcp = ((TCPPacket) packet);
        setupDataToDrillTable("TCP",
            tcp.timestamp,
            new IpDto(tcp.dst_ip.toString(), tcp.src_ip.toString()),
            new PortDto(tcp.dst_port, tcp.src_port),
            Arrays.toString(tcp.data));
        return 1;
      } else if (packet instanceof UDPPacket) {
        UDPPacket udp = ((UDPPacket) packet);
        setupDataToDrillTable("UDP",
            udp.timestamp,
            new IpDto(udp.dst_ip.toString(), udp.src_ip.toString()),
            new PortDto(udp.dst_port, udp.src_port),
            Arrays.toString(udp.data));
        return 1;
      }
      packet = parser.getPacket();
    }
    parser.closeFile();
    return 0;
  }

  private void setupDataToDrillTable(final String packetName,
                                     final long timestamp,
                                     final IpDto ip,
                                     final PortDto port,
                                     final String data) {
    for (ProjectedColumnInfo pci : projectedCols) {
      switch (pci.pcapColumn.getColumnName()) {
        case "Type":
          setStringColumnValue(packetName, pci);
          break;
        case "Timestamp":
          setTimestampColumnValue(timestamp, pci);
          break;
        case "dst_ip":
          setStringColumnValue(ip.getDst_ip(), pci);
          break;
        case "src_ip":
          setStringColumnValue(ip.getSrc_ip(), pci);
          break;
        case "dst_port":
          setIntegerColumnValue(port.getDst_port(), pci);
          break;
        case "src_port":
          setIntegerColumnValue(port.getSrc_port(), pci);
          break;
        case "Data":
          setStringColumnValue(data, pci);
      }
    }
  }

  private void setIntegerColumnValue(final int data, final ProjectedColumnInfo pci) {
    ((NullableIntVector.Mutator) pci.vv.getMutator())
        .setSafe(0, data);
  }

  private void setTimestampColumnValue(final long data, final ProjectedColumnInfo pci) {
    ((NullableTimeStampVector.Mutator) pci.vv.getMutator())
        .setSafe(0, data);
  }

  private void setStringColumnValue(final String data, final ProjectedColumnInfo pci) {
    ByteBuffer value = ByteBuffer.wrap(data.getBytes(UTF_8));
    ((NullableVarCharVector.Mutator) pci.vv.getMutator())
        .setSafe(0, value, 0, value.remaining());
  }
}
