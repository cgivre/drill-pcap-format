package org.apache.drill.exec.expr.fn.impl;

import io.netty.buffer.DrillBuf;
import org.apache.drill.exec.expr.DrillSimpleFunc;
import org.apache.drill.exec.expr.annotations.FunctionTemplate;
import org.apache.drill.exec.expr.annotations.Output;
import org.apache.drill.exec.expr.annotations.Param;
import org.apache.drill.exec.expr.annotations.Workspace;
import org.apache.drill.exec.expr.holders.BitHolder;
import org.apache.drill.exec.expr.holders.NullableVarCharHolder;
import org.apache.drill.exec.expr.holders.VarCharHolder;
import org.apache.drill.exec.expr.holders.BigIntHolder;
import org.apache.commons.net.util.SubnetUtils;
import javax.inject.Inject;

/* Copyright 2001-2004 The Apache Software Foundation.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


public class NetworkFunctions{
    static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NetworkFunctions.class);

    private NetworkFunctions() {}

    @FunctionTemplate(
        name = "inet_aton",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class InetAtonFunction implements DrillSimpleFunc {

        @Param
        NullableVarCharHolder inputTextA;

        @Output BigIntHolder out;

        @Inject
        DrillBuf buffer;


        public void setup() {
        }


        public void eval() {
            String ip_string = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(inputTextA.start, inputTextA.end, inputTextA.buffer);
            if( ip_string == null || ip_string.isEmpty() || ip_string.length() == 0 ){
                out.value = 0;
            } else {
                String[] ipAddressInArray = ip_string.split("\\.");

                long result = 0;
                for (int i = 0; i < ipAddressInArray.length; i++) {
                    int power = 3 - i;
                    int ip = Integer.parseInt(ipAddressInArray[i]);
                    result += ip * Math.pow(256, power);

                }

                out.value = result;
            }
        }


    }

    @FunctionTemplate(
        name = "inet_ntoa",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class InetNtoaFunction implements DrillSimpleFunc {

        @Param
        BigIntHolder in1;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;


        public void setup() {
        }


        public void eval() {
            StringBuilder result = new StringBuilder(15);

            long inputInt = in1.value;

            for (int i = 0; i < 4; i++) {

                result.insert(0,Long.toString(inputInt & 0xff));

                if (i < 3) {
                    result.insert(0,'.');
                }

                inputInt = inputInt >> 8;
            }

            String outputValue = result.toString();

            out.buffer = buffer;
            out.start = 0;
            out.end = outputValue.getBytes().length;
            buffer.setBytes(0, outputValue.getBytes());
        }


    }

    @FunctionTemplate(
        name = "is_private_ip",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class IsPrivateIP implements DrillSimpleFunc {

        @Param
        NullableVarCharHolder inputTextA;

        @Output BitHolder out;

        @Inject
        DrillBuf buffer;


        public void setup() {
        }


        public void eval() {
            String ip_string = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(inputTextA.start, inputTextA.end, inputTextA.buffer);

            String[] ipAddressInArray = ip_string.split("\\.");

            int result = 0;

            int[] octets = new int[3];

            for( int i = 0; i < 3; i++ ){
                octets[i] = Integer.parseInt( ipAddressInArray[i] );
                if( octets[i] > 255 || octets[i] < 0 ) {
                    result = 0;
                }
            }

            if( octets[0] == 192 && octets[1] == 168 ) {
                result = 1;
            }
            else if (octets[0] == 172 && octets [1] >= 16 && octets[1] <= 31 ){
                result = 1;
            }
            else if( octets[0] == 10 ) {
                result = 1;
            }
            else {
                result = 0;
            }

            out.value = result;
        }


    }

    @FunctionTemplate(
            name = "in_network",
            scope = FunctionTemplate.FunctionScope.SIMPLE,
            nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class InNetworkFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder input_ip;

        @Param
        VarCharHolder input_cidr;

        @Output
        BitHolder out;

        @Inject
        DrillBuf buffer;

        @Workspace
        SubnetUtils utils;

        public void setup() {
        }


        public void eval() {

            String ip_string = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(input_ip.start, input_ip.end, input_ip.buffer);
            String cidr_string = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(input_cidr.start, input_cidr.end, input_cidr.buffer);

            int result = 0;
            utils = new org.apache.commons.net.util.SubnetUtils(cidr_string);

            if( utils.getInfo().isInRange( ip_string ) ){
                result = 1;
            }
            else{
                result = 0;
            }

            out.value = result;

        }


    }

    @FunctionTemplate(
            name = "getAddressCount",
            scope = FunctionTemplate.FunctionScope.SIMPLE,
            nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class getAddressCountFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder input_cidr;

        @Output
        BigIntHolder out;

        @Inject
        DrillBuf buffer;

        @Workspace
        SubnetUtils utils;

        public void setup() {
        }

        public void eval() {

            String cidr_string = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(input_cidr.start, input_cidr.end, input_cidr.buffer);
            utils = new org.apache.commons.net.util.SubnetUtils(cidr_string);

            out.value = utils.getInfo().getAddressCount();

        }

    }

    @FunctionTemplate(
            name = "getBroadcastAddress",
            scope = FunctionTemplate.FunctionScope.SIMPLE,
            nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class getBroadcastAddressFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder input_cidr;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Workspace
        SubnetUtils utils;

        public void setup() {
        }

        public void eval() {

            String cidr_string = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(input_cidr.start, input_cidr.end, input_cidr.buffer);
            utils = new org.apache.commons.net.util.SubnetUtils(cidr_string);

            String outputValue = utils.getInfo().getBroadcastAddress();

            out.buffer = buffer;
            out.start = 0;
            out.end = outputValue.getBytes().length;
            buffer.setBytes(0, outputValue.getBytes());

        }

    }

    @FunctionTemplate(
            name = "getNetmask",
            scope = FunctionTemplate.FunctionScope.SIMPLE,
            nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class getNetmaskFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder input_cidr;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Workspace
        SubnetUtils utils;

        public void setup() {
        }

        public void eval() {

            String cidr_string = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(input_cidr.start, input_cidr.end, input_cidr.buffer);
            utils = new org.apache.commons.net.util.SubnetUtils(cidr_string);

            String outputValue = utils.getInfo().getNetmask();

            out.buffer = buffer;
            out.start = 0;
            out.end = outputValue.getBytes().length;
            buffer.setBytes(0, outputValue.getBytes());

        }

    }

    @FunctionTemplate(
            name = "getLowAddress",
            scope = FunctionTemplate.FunctionScope.SIMPLE,
            nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class getLowAddressFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder input_cidr;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Workspace
        SubnetUtils utils;

        public void setup() {
        }

        public void eval() {

            String cidr_string = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(input_cidr.start, input_cidr.end, input_cidr.buffer);
            utils = new org.apache.commons.net.util.SubnetUtils(cidr_string);

            String outputValue = utils.getInfo().getLowAddress();

            out.buffer = buffer;
            out.start = 0;
            out.end = outputValue.getBytes().length;
            buffer.setBytes(0, outputValue.getBytes());

        }

    }

    @FunctionTemplate(
            name = "getHighAddress",
            scope = FunctionTemplate.FunctionScope.SIMPLE,
            nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class getHighddressFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder input_cidr;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Workspace
        SubnetUtils utils;

        public void setup() {
        }

        public void eval() {

            String cidr_string = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(input_cidr.start, input_cidr.end, input_cidr.buffer);
            utils = new org.apache.commons.net.util.SubnetUtils(cidr_string);

            String outputValue = utils.getInfo().getHighAddress();

            out.buffer = buffer;
            out.start = 0;
            out.end = outputValue.getBytes().length;
            buffer.setBytes(0, outputValue.getBytes());

        }
    }

    @FunctionTemplate(
        name = "urlencode",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class urlencodeFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder input_string;

        @Output
        VarCharHolder output_string;

        @Inject
        DrillBuf buffer;

        public void setup() {
        }

        public void eval() {

            String url = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(input_string.start, input_string.end, input_string.buffer);

            String outputValue = "";
            try {
                outputValue = java.net.URLEncoder.encode(url, "UTF-8");
            }catch (Exception e){

            }
            output_string.buffer = buffer;
            output_string.start = 0;
            output_string.end = outputValue.getBytes().length;
            buffer.setBytes(0, outputValue.getBytes());

        }
    }

    @FunctionTemplate(
        name = "urldecode",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class urldecodeFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder input_string;

        @Output
        VarCharHolder output_string;

        @Inject
        DrillBuf buffer;

        public void setup() {
        }

        public void eval() {

            String url = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(input_string.start, input_string.end, input_string.buffer);

            String outputValue = "";
            try {
                outputValue = java.net.URLDecoder.decode(url, "UTF-8");
            }catch (Exception e){

            }
            output_string.buffer = buffer;
            output_string.start = 0;
            output_string.end = outputValue.getBytes().length;
            buffer.setBytes(0, outputValue.getBytes());

        }
    }

}