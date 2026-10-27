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

  # LMP/LIH/BV-19-C [Request Sniff Mode Exit]
  #
  # Verify that the IUT can request the Lower Tester to exit Sniff mode.
  # The IUT is the Central and initiates the service.
  #
  # The Initial Condition "the IUT has requested the Lower Tester into
  # Sniff mode" is the procedure of LMP/LIH/BV-18-C [Initiate Sniff Mode,
  # Central] (steps 7-13), which is therefore exercised here as well.
  #
  # LMP_SUPERVISION_TIMEOUT, LMP_QUALITY_OF_SERVICE(_REQ), LMP_FEATURES_REQ
  # and POLL slot timing are baseband procedures not modelled by the
  # controller and are skipped.
  async def test(self):
    # Test parameters.
    controller = self.controller
    peer_address = Address("11:22:33:44:55:66")
    t_sniff = 0x0012
    sniff_attempt = 0x0004
    sniff_timeout = 0x0002

    # Initial Condition: the IUT pages the Lower Tester to become the
    # Central of the piconet.
    controller.send_cmd(
        hci.CreateConnection(
            bd_addr=peer_address,
            packet_type=0x7FFF,
            page_scan_repetition_mode=hci.PageScanRepetitionMode.R1,
            allow_role_switch=hci.CreateConnectionRoleSwitch.REMAIN_CENTRAL,
        )
    )

    await self.expect_evt(
        hci.CreateConnectionStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    await self.expect_ll(
        ll.Page(
            source_address=controller.address,
            destination_address=peer_address,
            allow_role_switch=False,
        )
    )

    controller.send_ll(
        ll.PageResponse(
            source_address=peer_address,
            destination_address=controller.address,
            try_role_switch=False,
        ),
        phy=Phy.BrEdr,
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

    # BV-18-C step 7. The Upper Tester sends an HCI_Write_Link_Policy_Settings
    # command to the IUT with Link_Policy_Settings set to 0x0004 (Sniff Mode)
    # and receives a successful HCI_Command_Complete event in response.
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

    # BV-18-C step 8. The Upper Tester sends an HCI_Sniff_Mode command to
    # the IUT with Sniff_Max_Interval set to 0x0012, Sniff_Min_Interval set
    # to 0x0012, Sniff_Attempt set to 0x0004, and Sniff_Timeout set to 0x0002
    # and receives a successful HCI_Command_Status event in response.
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

    # BV-18-C step 11. The IUT sends an LMP_SNIFF_REQ PDU to the Lower
    # Tester with TSniff set to 18, Sniff_Attempt set to 4, and
    # Sniff_Timeout set to 2.
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

    # BV-18-C step 12. The Lower Tester responds to the IUT with an
    # LMP_ACCEPTED PDU with the LMP_SNIFF_REQ PDU Opcode.
    controller.send_ll(
        ll.SniffRsp(
            source_address=peer_address,
            destination_address=controller.address,
            status=ErrorCode.SUCCESS,
            interval=t_sniff,
        ),
        phy=Phy.BrEdr,
    )

    # BV-18-C step 13. The IUT sends a successful HCI_Mode_Change event to
    # the Upper Tester with Current_Mode set to 0x02 (Sniff Mode) and
    # Interval set to 0x0012.
    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.SNIFF,
            interval=t_sniff,
        )
    )

    # 1. The Upper Tester sends an HCI_Exit_Sniff_Mode command to the IUT
    #    with the Connection_Handle and receives a successful
    #    HCI_Command_Status event in response.
    controller.send_cmd(
        hci.ExitSniffMode(connection_handle=acl_connection_handle)
    )

    await self.expect_evt(
        hci.ExitSniffModeStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    # 2. The IUT sends an LMP_UNSNIFF_REQ PDU to the Lower Tester.
    await self.expect_ll(
        ll.UnsniffReq(
            source_address=controller.address,
            destination_address=peer_address,
        )
    )

    # 3. The Lower Tester responds with an LMP_ACCEPTED PDU with the
    #    LMP_UNSNIFF_REQ PDU Opcode.
    controller.send_ll(
        ll.UnsniffRsp(
            source_address=peer_address,
            destination_address=controller.address,
            status=ErrorCode.SUCCESS,
        ),
        phy=Phy.BrEdr,
    )

    # 6. The IUT sends a successful HCI_Mode_Change event to the Upper
    #    Tester with Current_Mode set to 0x00 (Active Mode).
    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.ACTIVE,
            interval=0,
        )
    )
