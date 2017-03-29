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
import com.mapr.PacketDecoder;
import com.mapr.PacketDecoder.Packet;
import io.netty.buffer.DrillBuf;
import org.apache.drill.common.exceptions.ExecutionSetupException;
import org.apache.drill.common.exceptions.UserException;
import org.apache.drill.common.expression.SchemaPath;
import org.apache.drill.common.types.TypeProtos;
import org.apache.drill.common.types.TypeProtos.MinorType;
import org.apache.drill.common.types.Types;
import org.apache.drill.exec.exception.SchemaChangeException;
import org.apache.drill.exec.expr.TypeHelper;
import org.apache.drill.exec.ops.FragmentContext;
import org.apache.drill.exec.ops.OperatorContext;
import org.apache.drill.exec.physical.impl.OutputMutator;
import org.apache.drill.exec.record.MaterializedField;
import org.apache.drill.exec.store.AbstractRecordReader;
import org.apache.drill.exec.store.pcap.schema.ColumnDTO;
import org.apache.drill.exec.store.pcap.schema.PcapTypes;
import org.apache.drill.exec.store.pcap.schema.Schema;
import org.apache.drill.exec.vector.NullableBitVector;
import org.apache.drill.exec.vector.NullableFloat8Vector;
import org.apache.drill.exec.vector.NullableIntVector;
import org.apache.drill.exec.vector.NullableTimeStampVector;
import org.apache.drill.exec.vector.NullableVarCharVector;
import org.apache.drill.exec.vector.ValueVector;
import org.apache.drill.exec.vector.complex.fn.FieldSelection;
import org.apache.drill.exec.vector.complex.impl.VectorContainerWriter;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class PcapRecordReader extends AbstractRecordReader {

  private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PcapRecordReader.class);

  private final Path hadoop;
  private final long start;
  private final long end;
  private final FieldSelection fieldSelection;
  private DrillBuf buffer;
  private VectorContainerWriter writer;

  private FileSystem fs;

  private final String opUserName;
  private final String queryUserName;

  private OutputMutator output;
  private OperatorContext context;
  private FileInputStream in;

  private ImmutableList<ProjectedColumnInfo> projectedCols;
  private static final Map<PcapTypes, TypeProtos.MinorType> TYPES;

  private static class ProjectedColumnInfo {
    ValueVector vv;
    ColumnDTO pcapColumn;
  }

  static {
    TYPES = ImmutableMap.<PcapTypes, TypeProtos.MinorType>builder()
        .put(PcapTypes.DOUBLE, TypeProtos.MinorType.FLOAT8)
        .build();
  }

  public PcapRecordReader(final FragmentContext fragmentContext,
                          final String inputPath,
                          final long start,
                          final long length,
                          final FileSystem fileSystem,
                          final List<SchemaPath> projectedColumns,
                          final String userName) {
    hadoop = new Path(inputPath);
    this.start = start;
    this.end = start + length;
    buffer = fragmentContext.getManagedBuffer();
    this.fs = fileSystem;
    this.opUserName = userName;
    this.queryUserName = fragmentContext.getQueryUserName();
    setColumns(projectedColumns);
    this.fieldSelection = FieldSelection.getFieldSelection(projectedColumns);
    try {
      this.in = new FileInputStream(getPathToFile(inputPath));
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    }
  }

  private String getPathToFile(String path) {
    return path.substring(5);
  }

  @Override
  public void setup(OperatorContext context, OutputMutator output) throws ExecutionSetupException {
    this.output = output;
    this.context = context;

  }

  @Override
  public int next() {
    try {
      setupProjectedColsIfItNull();
    } catch (SchemaChangeException sce) {
      log.warn("the addition of this field is incompatible with this OutputMutator's capabilities", sce);
    }
    try {
      parsePcapFilesAndPutItToTable(in);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return 1;
  }

  @Override
  public void close() throws Exception {

  }

  private void setupProjectedColsIfItNull() throws SchemaChangeException {
    if (projectedCols == null) {
      initCols(new Schema());
    }
  }

  private void initCols(Schema schema) throws SchemaChangeException {
    ImmutableList.Builder<ProjectedColumnInfo> pciBuilder = ImmutableList.builder();

    for (int i = 0; i < schema.getColumns().size(); i++) {

      ColumnDTO column = schema.getColumnByIndex(i);
      final String name = column.getColumnName();
      final PcapTypes type = column.getColumnType();
      TypeProtos.MinorType minorType = TYPES.get(type);

      if (isMinorTypeNull(minorType)) {
        logExceptionMessage(name, type);
        continue;
      }

      ProjectedColumnInfo pci = getProjectedColumnInfo(column, name, minorType);
      pciBuilder.add(pci);
    }
    projectedCols = pciBuilder.build();
  }

  private ProjectedColumnInfo getProjectedColumnInfo(ColumnDTO column, String name, MinorType minorType) throws SchemaChangeException {
    TypeProtos.MajorType majorType = getMajorType(minorType);

    MaterializedField field =
        MaterializedField.create(name, majorType);

    ValueVector vector =
        getValueVector(minorType, majorType, field);

    return getProjectedColumnInfo(column, vector);
  }

  private ProjectedColumnInfo getProjectedColumnInfo(ColumnDTO column, ValueVector vector) {
    ProjectedColumnInfo pci = new ProjectedColumnInfo();
    pci.vv = vector;
    pci.pcapColumn = column;
    return pci;
  }

  private TypeProtos.MajorType getMajorType(TypeProtos.MinorType minorType) {
    return Types.optional(minorType);
  }

  private ValueVector getValueVector(TypeProtos.MinorType minorType, TypeProtos.MajorType majorType, MaterializedField field) throws SchemaChangeException {
    final Class<? extends ValueVector> clazz = TypeHelper.getValueVectorClass(
        minorType, majorType.getMode());
    ValueVector vector = output.addField(field, clazz);
    vector.allocateNew();
    return vector;
  }

  private boolean isMinorTypeNull(TypeProtos.MinorType minorType) {
    return minorType == null;
  }

  private void logExceptionMessage(String name, PcapTypes type) {
    log.warn("Ignoring column that is unsupported.", UserException
        .unsupportedError()
        .message(
            "A column you queried has a data type that is not currently supported by the OpenTSDB storage plugin. "
                + "The column's name was %s and its OpenTSDB data type was %s. ",
            name, type.toString())
        .addContext("column Name", name)
        .addContext("plugin", "openTSDB")
        .build(log));
  }

  private void setupDataToDrillTable(Packet packet) {
    for (ProjectedColumnInfo pci : projectedCols) {
      switch (pci.pcapColumn.getColumnName()) {
        case "Source":
          setStringColumnValue(Arrays.toString(packet.getEthernetDestination()), pci);
          break;
        case "Packet Length":
          setIntegerColumnValue(packet.getPacketLength(), pci);
          break;
        case "Timestamp":
          setTimestampColumnValue(packet.getTimestamp(), pci);
          break;
        case "TCP":
          setBooleanColumnValue(packet.isTcpPacket(), pci);
          break;
        case "UDP":
          setBooleanColumnValue(packet.isUdpPacket(), pci);
          break;
      }
    }
  }

  private void setBooleanColumnValue(boolean data, ProjectedColumnInfo pci) {
    ((NullableBitVector.Mutator) pci.vv.getMutator())
        .setSafe(0, data ? 1 : 0);
  }

  private void setIntegerColumnValue(int data, ProjectedColumnInfo pci) {
    ((NullableIntVector.Mutator) pci.vv.getMutator())
        .setSafe(0, data);
  }


  private void setTimestampColumnValue(long data, ProjectedColumnInfo pci) {
    ((NullableTimeStampVector.Mutator) pci.vv.getMutator())
        .setSafe(0, data);
  }

  private void setStringColumnValue(String data, ProjectedColumnInfo pci) {
    if (data == null) {
      data = "null";
    }
    ByteBuffer value = ByteBuffer.wrap(data.getBytes(UTF_8));
    ((NullableVarCharVector.Mutator) pci.vv.getMutator())
        .setSafe(0, value, 0, value.remaining());
  }

  public void parsePcapFilesAndPutItToTable(FileInputStream in) throws IOException {
    PacketDecoder pd = new PacketDecoder(in);
    PacketDecoder.Packet p = pd.packet();

    byte[] buffer = new byte[100000];
    int validBytes = in.read(buffer);

    int offset = 0;
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
      setupDataToDrillTable(p);
    }
  }
}
