################################################################################
 #  INTEL CONFIDENTIAL
 #
 #  Copyright (c) 2021 Intel Corporation
 #  All Rights Reserved.
 #
 #  This software and the related documents are Intel copyrighted materials,
 #  and your use of them is governed by the express license under which they
 #  were provided to you ("License"). Unless the License provides otherwise,
 #  you may not use, modify, copy, publish, distribute, disclose or transmit this
 #  software or the related documents without Intel's prior written permission.
 #
 #  This software and the related documents are provided as is, with no express or
 #  implied warranties, other than those that are expressly stated in the License.
 #################################################################################

import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
from p4testutils.misc_utils import *
from p4testutils.bfrt_utils import *
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
import random
from scapy.all import *

logger = get_logger()
swports = get_sw_ports()

client_id = 0
p4_name = "voting"
arch = testutils.test_param_get("arch")

class Bit64RegisterTest(BfRuntimeTest):
    """@brief This test sends 2 packets, and checks if the second packet is sent back with the previous packet's srcAddress in its (custom) headers.
    """

    def setUp(self):
        client_id = 0
        p4_name = "voting"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def tearDown(self):
        pass

    def clearTable(self):
        pass

    def runTest(self):
    	ig_port = swports[1]
    	pkt = Ether(src='11:11:11:cc:cc:cc',dst='00:11:22:33:44:55') / bytes(64)
    	exp_pkt =  Ether(src='00:11:22:33:44:55',dst='11:11:11:cc:cc:cc') / bytes.fromhex('0000111111cccccc') / bytes(56)
    	testutils.send_packet(self, ig_port, pkt) # send first time
    	testutils.verify_packet(self, None, ig_port) # not verifying the first packet
    	testutils.send_packet(self, ig_port, pkt) # send again, now we should receive the src mac address in the header
    	testutils.verify_packet(self, exp_pkt, ig_port) # verify

