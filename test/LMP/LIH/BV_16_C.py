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

  # LMP/LIH/BV-16-C [Exit Sniff Mode]
  async def test(self):
    controller = self.controller
    peer_address = Address("11:22:33:44:55:66")

    # Initial condition: the Lower Tester is the Central and initiates the
    # connection. The IUT is the Peripheral.
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

    # Initial condition: the Supervision Timeout is disabled.
    # Note: LMP_SUPERVISION_TIMEOUT is not modeled by Rootcanal; skipped.

    # Initial condition: the IUT is already in Sniff mode by request of the
    # Lower Tester. Sniff mode must be allowed by the link policy settings
    # for the IUT to accept the request.
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

    await self.expect_ll(
        ll.SniffRsp(
            source_address=controller.address,
            destination_address=peer_address,
            status=ErrorCode.SUCCESS,
            interval=18,
        )
    )

    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.SNIFF,
            interval=18,
        )
    )

    # 1. The Lower Tester sends an LMP_UNSNIFF_REQ PDU to the IUT.
    controller.send_ll(
        ll.UnsniffReq(
            source_address=peer_address,
            destination_address=controller.address,
        ),
        phy=Phy.BrEdr,
    )

    # 2. The IUT responds with an LMP_ACCEPTED PDU with the LMP_UNSNIFF_REQ
    #    PDU Opcode (modeled as ll.UnsniffRsp).
    await self.expect_ll(
        ll.UnsniffRsp(
            source_address=controller.address,
            destination_address=peer_address,
            status=ErrorCode.SUCCESS,
        )
    )

    # 3. The IUT sends a successful HCI_Mode_Change event to the Upper Tester
    #    with Current_Mode set to 0x00 (Active Mode).
    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.ACTIVE,
            interval=0,
        )
    )

    # 4. The Lower Tester sends POLL packets to the IUT in all Central slots.
    # Note: baseband slot polling is not modeled by Rootcanal; skipped.
