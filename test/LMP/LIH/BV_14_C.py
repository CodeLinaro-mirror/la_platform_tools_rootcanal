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

from dataclasses import dataclass
from rootcanal.bluetooth import Address
from rootcanal.controller import Phy
from rootcanal.packets import hci
from rootcanal.packets import ll
from rootcanal.packets.hci import ErrorCode
from test.controller_test import ControllerTest


class Test(ControllerTest):

  # LMP/LIH/BV-14-C [Enter Sniff Mode]
  async def test(self):
    controller = self.controller
    peer_address = Address("11:22:33:44:55:66")

    # Establish connection: Lower Tester (Central) pages IUT (Peripheral).
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

    # ---------------------------------------------------------------------
    # 1. Lower Tester sends LMP_SUPERVISION_TIMEOUT and LMP_QUALITY_OF_SERVICE_REQ
    # 2. Alternative 2A / 2B (HCI_QoS_Setup_Complete / Flow_Specification)
    # Note: Skipped as Rootcanal does not currently model supervision timeout PDUs.
    # ---------------------------------------------------------------------

    # ---------------------------------------------------------------------
    # 3. Upper Tester sends HCI_Write_Link_Policy_Settings (0x0004 = Sniff Mode).
    # ---------------------------------------------------------------------
    controller.send_cmd(
        hci.WriteLinkPolicySettings(
            connection_handle=acl_connection_handle,
            link_policy_settings=hci.LinkPolicy.ENABLE_SNIFF_MODE,
        )
    )

    # 5. IUT sends successful HCI_Command_Complete event.
    await self.expect_evt(
        hci.WriteLinkPolicySettingsComplete(
            status=ErrorCode.SUCCESS,
            num_hci_command_packets=1,
            connection_handle=acl_connection_handle,
        )
    )

    # ---------------------------------------------------------------------
    # 4. Lower Tester sends LMP_FEATURES_REQ.
    # 6. IUT sends LMP_FEATURES_RES.
    # Note: Skipped as Rootcanal models features implicitly.
    # ---------------------------------------------------------------------

    # ---------------------------------------------------------------------
    # 7. Lower Tester sends LMP_SNIFF_REQ:
    #    Timing_Control_Flags bits 0 & 2 = 0, DSniff=0, TSniff=18,
    #    Sniff_Attempt=4, Sniff_Timeout=2.
    # ---------------------------------------------------------------------
    controller.send_ll(
        ll.SniffReq(
            source_address=peer_address,
            destination_address=controller.address,
            timing_control_flags=0,
            d_sniff=0,
            t_sniff=18,
            sniff_attempt=4,
            sniff_timeout=2,
        ),
        phy=Phy.BrEdr,
    )

    # ---------------------------------------------------------------------
    # 8. Alternative 8A:
    # 8A.1. IUT responds with LMP_ACCEPTED (modeled as ll.SniffRsp).
    # ---------------------------------------------------------------------
    await self.expect_ll(
        ll.SniffRsp(
            source_address=controller.address,
            destination_address=peer_address,
            status=ErrorCode.SUCCESS,
            interval=18,
        )
    )

    # 8A.2. IUT sends successful HCI_Mode_Change event (0x02 = Sniff Mode).
    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.SNIFF,
            interval=18,
        )
    )

    # ---------------------------------------------------------------------
    # 8A.3. Lower Tester sends LMP_UNSNIFF_REQ.
    # ---------------------------------------------------------------------
    controller.send_ll(
        ll.UnsniffReq(
            source_address=peer_address,
            destination_address=controller.address,
        ),
        phy=Phy.BrEdr,
    )

    # 8A.4. IUT responds with LMP_ACCEPTED (modeled as ll.UnsniffRsp).
    await self.expect_ll(
        ll.UnsniffRsp(
            source_address=controller.address,
            destination_address=peer_address,
            status=ErrorCode.SUCCESS,
        )
    )

    # 8A.5. IUT sends successful HCI_Mode_Change event (0x00 = Active Mode).
    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.ACTIVE,
            interval=0,
        )
    )

    # ---------------------------------------------------------------------
    # 8A.6. Lower Tester sends LMP_SNIFF_REQ with bits 0 and 2 set to 1 (0x05):
    # ---------------------------------------------------------------------
    controller.send_ll(
        ll.SniffReq(
            source_address=peer_address,
            destination_address=controller.address,
            timing_control_flags=0x05,  # (1 << 0) | (1 << 2)
            d_sniff=0,
            t_sniff=18,
            sniff_attempt=4,
            sniff_timeout=2,
        ),
        phy=Phy.BrEdr,
    )

    # 8A.7. IUT responds with LMP_ACCEPTED (ll.SniffRsp).
    await self.expect_ll(
        ll.SniffRsp(
            source_address=controller.address,
            destination_address=peer_address,
            status=ErrorCode.SUCCESS,
            interval=18,
        )
    )

    # 9. IUT sends successful HCI_Mode_Change event (Sniff Mode, interval=18).
    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.SNIFF,
            interval=18,
        )
    )

    # ---------------------------------------------------------------------
    # 10. Lower Tester sends POLL packets according to Figure 4.8-20.
    # Note: Skipped as baseband slot polling is not modeled in Rootcanal.
    # ---------------------------------------------------------------------
