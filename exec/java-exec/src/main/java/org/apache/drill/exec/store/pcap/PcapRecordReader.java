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
import org.apache.drill.common.exceptions.ExecutionSetupException;
import org.apache.drill.common.expression.SchemaPath;
import org.apache.drill.common.types.TypeProtos;
import org.apache.drill.common.types.TypeProtos.MajorType;
import org.apache.drill.common.types.TypeProtos.MinorType;
import org.apache.drill.common.types.Types;
import org.apache.drill.exec.exception.SchemaChangeException;
import org.apache.drill.exec.expr.TypeHelper;
import org.apache.drill.exec.ops.OperatorContext;
import org.apache.drill.exec.physical.impl.OutputMutator;
import org.apache.drill.exec.record.MaterializedField;
import org.apache.drill.exec.store.AbstractRecordReader;
import org.apache.drill.exec.store.pcap.decoder.PacketDecoder;
import org.apache.drill.exec.store.pcap.decoder.PacketDecoder.Packet;
import org.apache.drill.exec.store.pcap.dto.ColumnDto;
import org.apache.drill.exec.store.pcap.dto.PacketDto;
import org.apache.drill.exec.store.pcap.schema.PcapTypes;
import org.apache.drill.exec.store.pcap.schema.Schema;
import org.apache.drill.exec.vector.NullableIntVector;
import org.apache.drill.exec.vector.NullableTimeStampVector;
import org.apache.drill.exec.vector.NullableVarCharVector;
import org.apache.drill.exec.vector.ValueVector;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class PcapRecordReader extends AbstractRecordReader {

  private OutputMutator output;
  private OperatorContext context;

  private final PacketDecoder decoder;
  private ImmutableList<ProjectedColumnInfo> projectedCols;

  private byte[] buffer = new byte[100000];
  private int offset = 0;
  private InputStream in;
  private int validBytes;

  private static final Map<PcapTypes, MinorType> TYPES;

  private static class ProjectedColumnInfo {
    ValueVector vv;
    ColumnDto pcapColumn;
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
    try {
      this.in = new FileInputStream(getPathToFile(inputPath));
      this.decoder = getPacketDecoder();
      validBytes = in.read(buffer);
    } catch (IOException e) {
      throw new RuntimeException("File " + getPathToFile(inputPath) + " not Found");
    }
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
    try {
      return parsePcapFilesAndPutItToTable();
    } catch (IOException io) {
      throw new RuntimeException("Trouble with reading packets in file!");
    }
  }

  @Override
  public void close() throws Exception {
  }

  private PacketDecoder getPacketDecoder() {
    try {
      return new PacketDecoder(in);
    } catch (IOException io) {
      throw new RuntimeException("File Not Found or some I/O issue");
    }
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
    ColumnDto column;

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

  private ProjectedColumnInfo getProjectedColumnInfo(final ColumnDto column,
                                                     final String name,
                                                     final MinorType minorType) {
    TypeProtos.MajorType majorType = getMajorType(minorType);

    MaterializedField field =
        MaterializedField.create(name, majorType);

    ValueVector vector =
        getValueVector(minorType, majorType, field);

    return getProjectedColumnInfo(column, vector);
  }

  private ProjectedColumnInfo getProjectedColumnInfo(final ColumnDto column, final ValueVector vector) {
    ProjectedColumnInfo pci = new ProjectedColumnInfo();
    pci.vv = vector;
    pci.pcapColumn = column;
    return pci;
  }

  private MajorType getMajorType(final MinorType minorType) {
    return Types.optional(minorType);
  }

  private ValueVector getValueVector(final MinorType minorType,
                                     final MajorType majorType,
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

  private int parsePcapFilesAndPutItToTable() throws IOException {
    Packet packet = decoder.packet();
    int networkType = decoder.getNetwork();
    while (offset < validBytes) {

      if (validBytes - offset < 9000) {
        System.arraycopy(buffer, 0, buffer, offset, validBytes - offset);
        validBytes = validBytes - offset;
        offset = 0;

        int n = in.read(buffer, validBytes, buffer.length - validBytes);
        if (n > 0) {
          validBytes += n;
        }
      }

      offset = decoder.decodePacket(buffer, offset, packet);

      if (addDataToTable(packet, networkType)) {
        return 1;
      }
    }
    return 0;
  }

  private boolean addDataToTable(final Packet packet, final int networkType) {
    String packetName;
    if (packet.isTcpPacket()) {
      packetName = "TCP";
    } else if (packet.isUdpPacket()) {
      packetName = "UDP";
    } else {
      return false;
    }
    setupDataToDrillTable(new PacketDto(packetName, networkType, packet));
    return true;
  }

  private void setupDataToDrillTable(final PacketDto packet) {
    for (ProjectedColumnInfo pci : projectedCols) {
      switch (pci.pcapColumn.getColumnName()) {
        case "Type":
          setStringColumnValue(packet.getPacketName(), pci);
          break;
        case "Timestamp":
          setTimestampColumnValue(packet.getTimestamp(), pci);
          break;
        case "Network":
          setIntegerColumnValue(packet.getNetwork(), pci);
          break;
        case "dst_ip":
          setStringColumnValue(packet.getIp().getDst_ip().getHostAddress(), pci);
          break;
        case "src_ip":
          setStringColumnValue(packet.getIp().getSrc_ip().getHostAddress(), pci);
          break;
        case "src_port":
          setIntegerColumnValue(packet.getSrc_port(), pci);
          break;
        case "dst_port":
          setIntegerColumnValue(packet.getDst_port(), pci);
          break;
        case "packet_length":
          setIntegerColumnValue(packet.getPacketLength(), pci);
          break;
        case "data":
          if (packet.getData() != null) {
            setStringColumnValue(Arrays.toString(packet.getData()), pci);
          } else {
            setStringColumnValue("[]", pci);
          }
          break;
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