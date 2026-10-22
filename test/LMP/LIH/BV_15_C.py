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

  # LMP/LIH/BV-15-C [Initiate Sniff Mode, Peripheral]
  #
  # Verify that the IUT can request the Lower Tester to enter Sniff mode.
  # The IUT is the Peripheral and initiates the service by requesting.
  # The Lower Tester is the Central and accepts the request.
  #
  # Steps 1-2 (LMP_SUPERVISION_TIMEOUT, LMP_QUALITY_OF_SERVICE_REQ),
  # 5-6 (LMP_FEATURES_REQ/RES) and 10 (POLL slot timing) are baseband
  # procedures not modelled by the controller and are skipped.
  async def test(self):
    # Test parameters.
    controller = self.controller
    peer_address = Address("11:22:33:44:55:66")
    t_sniff = 0x0012
    sniff_attempt = 0x0004
    sniff_timeout = 0x0002

    # Initial Condition: an ACL connection has been established,
    # the IUT is the Peripheral.
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

    # 3. The Upper Tester sends an HCI_Write_Link_Policy_Settings command
    #    to the IUT with Link_Policy_Settings set to 0x0004 (Sniff Mode)
    #    and receives a successful HCI_Command_Complete event in response.
    controller.send_cmd(
        hci.WriteLinkPolicySettings(
            connection_handle=acl_connection_handle,
            link_policy_settings=hci.LinkPolicy.ENABLE_SNIFF_MODE,
        )
    )

    await self.expect_evt(
        hci.WriteLinkPolicySettingsComplete(
            status=ErrorCode.SUCCESS,
            num_hci_command_packets=1,
            connection_handle=acl_connection_handle,
        )
    )

    # 4. The Upper Tester sends an HCI_Sniff_Mode command to the IUT with
    #    Sniff_Max_Interval set to 0x0012, Sniff_Min_Interval set to
    #    0x0012, Sniff_Attempt set to 0x0004, and Sniff_Timeout set to
    #    0x0002 and receives a successful HCI_Command_Status event.
    controller.send_cmd(
        hci.SniffMode(
            connection_handle=acl_connection_handle,
            sniff_max_interval=t_sniff,
            sniff_min_interval=t_sniff,
            sniff_attempt=sniff_attempt,
            sniff_timeout=sniff_timeout,
        )
    )

    await self.expect_evt(
        hci.SniffModeStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1)
    )

    # 7. The IUT sends an LMP_SNIFF_REQ PDU to the Lower Tester with
    #    Timing_Control_Flags, DSniff, TSniff set to 18, Sniff_Attempt
    #    set to 4, and Sniff_Timeout set to 2.
    await self.expect_ll(
        ll.SniffReq(
            source_address=controller.address,
            destination_address=peer_address,
            timing_control_flags=self.Any,
            d_sniff=self.Any,
            t_sniff=t_sniff,
            sniff_attempt=sniff_attempt,
            sniff_timeout=sniff_timeout,
        )
    )

    # 8. The Lower Tester responds to the IUT with an LMP_ACCEPTED PDU
    #    with the LMP_SNIFF_REQ PDU Opcode.
    controller.send_ll(
        ll.SniffRsp(
            source_address=peer_address,
            destination_address=controller.address,
            status=ErrorCode.SUCCESS,
            interval=t_sniff,
        ),
        phy=Phy.BrEdr,
    )

    # 9. The IUT sends a successful HCI_Mode_Change event to the Upper
    #    Tester with Current_Mode set to 0x02 (Sniff Mode) and Interval
    #    set to 0x0012.
    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.SNIFF,
            interval=t_sniff,
        )
    )
