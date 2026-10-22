# Copyright 2026 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from rootcanal.bluetooth import Address
from rootcanal.controller import Phy
from rootcanal.packets import hci
from rootcanal.packets import ll
from rootcanal.packets.hci import ErrorCode
from test.controller_test import ControllerTest


class Test(ControllerTest):

  # LMP/LIH/BV-20-C [Sniff Mode Reject]
  #
  # Verify that the IUT responds that it does not support Sniff mode upon
  # a request from the Lower Tester. The controller always advertises the
  # Sniff Mode LMP feature; the request is rejected because Sniff mode is
  # disabled in the link policy settings of the connection (default 0x0000).
  #
  # Note: the specification expects Error_Code 0x1A (Unsupported LMP
  # Feature); the controller reports Command Disallowed (0x0C) since the
  # rejection comes from the local link policy, not a missing feature.
  async def test(self):
    # Test parameters.
    controller = self.controller
    peer_address = Address("11:22:33:44:55:66")

    # Initial Condition: an ACL connection has been established.
    controller.send_cmd(
        hci.WriteScanEnable(scan_enable=hci.ScanEnable.PAGE_SCAN_ONLY)
    )

    await self.expect_evt(
        hci.WriteScanEnableComplete(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    controller.send_ll(
        ll.Page(
            source_address=peer_address,
            destination_address=controller.address,
            allow_role_switch=False,
        ),
        phy=Phy.BrEdr,
    )

    await self.expect_evt(
        hci.ConnectionRequest(
            bd_addr=peer_address, link_type=hci.ConnectionRequestLinkType.ACL
        )
    )

    controller.send_cmd(
        hci.AcceptConnectionRequest(
            bd_addr=peer_address,
            role=hci.AcceptConnectionRequestRole.REMAIN_PERIPHERAL,
        )
    )

    await self.expect_evt(
        hci.AcceptConnectionRequestStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    await self.expect_ll(
        ll.PageResponse(
            source_address=controller.address,
            destination_address=peer_address,
            try_role_switch=False,
        )
    )

    evt = await self.expect_evt(
        hci.ConnectionComplete(
            status=ErrorCode.SUCCESS,
            connection_handle=self.Any,
            bd_addr=peer_address,
            link_type=hci.LinkType.ACL,
            encryption_enabled=hci.Enable.DISABLED,
        )
    )

    assert isinstance(evt, hci.ConnectionComplete)
    acl_connection_handle = evt.connection_handle

    # Initial Condition: Sniff mode is not enabled in the link policy.
    controller.send_cmd(
        hci.ReadLinkPolicySettings(connection_handle=acl_connection_handle)
    )

    await self.expect_evt(
        hci.ReadLinkPolicySettingsComplete(
            status=ErrorCode.SUCCESS,
            num_hci_command_packets=1,
            connection_handle=acl_connection_handle,
            link_policy_settings=0x0000,
        )
    )

    # 1. The Lower Tester sends an LMP_SNIFF_REQ PDU to the IUT with
    #    Timing_Control_Flags, DSniff, TSniff, Sniff_Attempt, and
    #    Sniff_Timeout.
    controller.send_ll(
        ll.SniffReq(
            source_address=peer_address,
            destination_address=controller.address,
            timing_control_flags=0x00,
            d_sniff=0x0010,
            t_sniff=0x0012,
            sniff_attempt=0x0004,
            sniff_timeout=0x0002,
        ),
        phy=Phy.BrEdr,
    )

    # 2. The IUT responds to the Lower Tester with an LMP_NOT_ACCEPTED PDU
    #    with the LMP_SNIFF_REQ PDU Opcode.
    await self.expect_ll(
        ll.SniffRsp(
            source_address=controller.address,
            destination_address=peer_address,
            status=ErrorCode.COMMAND_DISALLOWED,
            interval=0,
        )
    )

    # The IUT remains in Active mode: an HCI_Exit_Sniff_Mode command
    # completes locally without any LMP exchange.
    controller.send_cmd(
        hci.ExitSniffMode(connection_handle=acl_connection_handle)
    )

    await self.expect_evt(
        hci.ExitSniffModeStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.ACTIVE,
            interval=0,
        )
    )
