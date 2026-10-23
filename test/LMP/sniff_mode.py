# Copyright 2026 Google LLC
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
  """Sniff mode tests for the BR/EDR controller.

  Verify the HCI_Sniff_Mode and HCI_Exit_Sniff_Mode parameter validation,
  the handling of LMP sniff requests and responses in Active and Sniff mode,
  the renegotiation of the sniff interval, the rejection of a Role Switch
  while in Sniff mode, and that a rejected request leaves the connection
  mode unchanged.
  """

  peer_address = Address("11:22:33:44:55:66")
  t_sniff = 0x0012
  sniff_attempt = 0x0004
  sniff_timeout = 0x0002

  async def establish_acl_connection_peripheral(self) -> int:
    """Lower Tester (Central) pages the IUT (Peripheral).

    Returns the ACL connection handle.
    """
    controller = self.controller
    peer_address = self.peer_address

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

    return evt.connection_handle

  async def write_link_policy_settings(
      self, acl_connection_handle: int, settings: int
  ):
    self.controller.send_cmd(
        hci.WriteLinkPolicySettings(
            connection_handle=acl_connection_handle,
            link_policy_settings=settings,
        )
    )

    await self.expect_evt(
        hci.WriteLinkPolicySettingsComplete(
            status=ErrorCode.SUCCESS,
            num_hci_command_packets=1,
            connection_handle=acl_connection_handle,
        )
    )

  async def enter_sniff_mode(self, acl_connection_handle: int):
    """Lower Tester requests Sniff mode, the IUT accepts."""
    controller = self.controller
    peer_address = self.peer_address

    controller.send_ll(
        ll.SniffReq(
            source_address=peer_address,
            destination_address=controller.address,
            timing_control_flags=0x00,
            d_sniff=self.t_sniff - 2,
            t_sniff=self.t_sniff,
            sniff_attempt=self.sniff_attempt,
            sniff_timeout=self.sniff_timeout,
        ),
        phy=Phy.BrEdr,
    )

    await self.expect_ll(
        ll.SniffRsp(
            source_address=controller.address,
            destination_address=peer_address,
            status=ErrorCode.SUCCESS,
            interval=self.t_sniff,
        )
    )

    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.SNIFF,
            interval=self.t_sniff,
        )
    )

  async def send_sniff_mode(self, acl_connection_handle: int, t_sniff: int):
    """Host requests Sniff mode; the IUT sends LMP_SNIFF_REQ to the peer."""
    controller = self.controller

    controller.send_cmd(
        hci.SniffMode(
            connection_handle=acl_connection_handle,
            sniff_max_interval=t_sniff,
            sniff_min_interval=t_sniff,
            sniff_attempt=self.sniff_attempt,
            sniff_timeout=self.sniff_timeout,
        )
    )

    await self.expect_evt(
        hci.SniffModeStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1)
    )

    await self.expect_ll(
        ll.SniffReq(
            source_address=controller.address,
            destination_address=self.peer_address,
            timing_control_flags=self.Any,
            d_sniff=self.Any,
            t_sniff=t_sniff,
            sniff_attempt=self.sniff_attempt,
            sniff_timeout=self.sniff_timeout,
        )
    )

  # HCI_Sniff_Mode is rejected with Command Disallowed when Sniff mode is
  # not enabled in the link policy settings of the connection.
  async def test_sniff_mode_disallowed_by_link_policy(self):
    controller = self.controller
    acl_connection_handle = await self.establish_acl_connection_peripheral()

    controller.send_cmd(
        hci.SniffMode(
            connection_handle=acl_connection_handle,
            sniff_max_interval=self.t_sniff,
            sniff_min_interval=self.t_sniff,
            sniff_attempt=self.sniff_attempt,
            sniff_timeout=self.sniff_timeout,
        )
    )

    await self.expect_evt(
        hci.SniffModeStatus(
            status=ErrorCode.COMMAND_DISALLOWED, num_hci_command_packets=1
        )
    )

  # HCI_Sniff_Mode and HCI_Exit_Sniff_Mode are rejected with Unknown
  # Connection Identifier for an invalid connection handle.
  async def test_sniff_mode_unknown_connection(self):
    controller = self.controller
    acl_connection_handle = await self.establish_acl_connection_peripheral()

    controller.send_cmd(
        hci.SniffMode(
            connection_handle=acl_connection_handle + 1,
            sniff_max_interval=self.t_sniff,
            sniff_min_interval=self.t_sniff,
            sniff_attempt=self.sniff_attempt,
            sniff_timeout=self.sniff_timeout,
        )
    )

    await self.expect_evt(
        hci.SniffModeStatus(
            status=ErrorCode.UNKNOWN_CONNECTION, num_hci_command_packets=1
        )
    )

    controller.send_cmd(
        hci.ExitSniffMode(connection_handle=acl_connection_handle + 1)
    )

    await self.expect_evt(
        hci.ExitSniffModeStatus(
            status=ErrorCode.UNKNOWN_CONNECTION, num_hci_command_packets=1
        )
    )

  # HCI_Sniff_Mode validates the interval, attempt and timeout parameters
  # (Vol 4, Part E § 7.2.2).
  async def test_sniff_mode_invalid_parameters(self):
    controller = self.controller
    acl_connection_handle = await self.establish_acl_connection_peripheral()
    await self.write_link_policy_settings(
        acl_connection_handle, hci.LinkPolicy.ENABLE_SNIFF_MODE
    )

    invalid_parameters = [
        # Sniff_Max_Interval < Sniff_Min_Interval.
        dict(sniff_max_interval=0x0010, sniff_min_interval=0x0012),
        # Odd intervals (must be an even number of slots).
        dict(sniff_max_interval=0x0013, sniff_min_interval=0x0012),
        dict(sniff_max_interval=0x0012, sniff_min_interval=0x0011),
        # Intervals out of range [0x0002, 0xFFFE].
        dict(sniff_max_interval=0x0012, sniff_min_interval=0x0000),
        dict(sniff_max_interval=0xFFFF, sniff_min_interval=0x0012),
        # Sniff_Attempt out of range [0x0001, 0x7FFF].
        dict(sniff_attempt=0x0000),
        dict(sniff_attempt=0x8000),
        # Sniff_Timeout out of range [0x0000, 0x7FFF].
        dict(sniff_timeout=0x8000),
    ]

    for parameters in invalid_parameters:
      command = dict(
          connection_handle=acl_connection_handle,
          sniff_max_interval=self.t_sniff,
          sniff_min_interval=self.t_sniff,
          sniff_attempt=self.sniff_attempt,
          sniff_timeout=self.sniff_timeout,
      )
      command.update(parameters)
      controller.send_cmd(hci.SniffMode(**command))

      await self.expect_evt(
          hci.SniffModeStatus(
              status=ErrorCode.INVALID_HCI_COMMAND_PARAMETERS,
              num_hci_command_packets=1,
          )
      )

  # An LMP_UNSNIFF_REQ received on a connection in Active mode is rejected
  # and no Mode Change event is generated.
  async def test_unsniff_request_in_active_mode(self):
    controller = self.controller
    peer_address = self.peer_address
    acl_connection_handle = await self.establish_acl_connection_peripheral()

    controller.send_ll(
        ll.UnsniffReq(
            source_address=peer_address,
            destination_address=controller.address,
        ),
        phy=Phy.BrEdr,
    )

    await self.expect_ll(
        ll.UnsniffRsp(
            source_address=controller.address,
            destination_address=peer_address,
            status=ErrorCode.COMMAND_DISALLOWED,
        )
    )

    # The connection is still in Active mode.
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

  # When the peer rejects the LMP_UNSNIFF_REQ, the connection remains in
  # Sniff mode and the failure is reported to the Host with the current
  # sniff interval.
  async def test_exit_sniff_mode_rejected_by_peer(self):
    controller = self.controller
    peer_address = self.peer_address
    acl_connection_handle = await self.establish_acl_connection_peripheral()
    await self.write_link_policy_settings(
        acl_connection_handle, hci.LinkPolicy.ENABLE_SNIFF_MODE
    )
    await self.enter_sniff_mode(acl_connection_handle)

    controller.send_cmd(
        hci.ExitSniffMode(connection_handle=acl_connection_handle)
    )

    await self.expect_evt(
        hci.ExitSniffModeStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    await self.expect_ll(
        ll.UnsniffReq(
            source_address=controller.address,
            destination_address=peer_address,
        )
    )

    controller.send_ll(
        ll.UnsniffRsp(
            source_address=peer_address,
            destination_address=controller.address,
            status=ErrorCode.UNSPECIFIED_ERROR,
        ),
        phy=Phy.BrEdr,
    )

    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.UNSPECIFIED_ERROR,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.SNIFF,
            interval=self.t_sniff,
        )
    )

    # The connection is still in Sniff mode: a second exit request
    # goes through the LMP exchange again.
    controller.send_cmd(
        hci.ExitSniffMode(connection_handle=acl_connection_handle)
    )

    await self.expect_evt(
        hci.ExitSniffModeStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    await self.expect_ll(
        ll.UnsniffReq(
            source_address=controller.address,
            destination_address=peer_address,
        )
    )

  # The Host can re-negotiate the sniff interval while already in Sniff
  # mode, even if Sniff mode was since disabled in the link policy.
  async def test_sniff_mode_renegotiation(self):
    controller = self.controller
    peer_address = self.peer_address
    acl_connection_handle = await self.establish_acl_connection_peripheral()
    await self.write_link_policy_settings(
        acl_connection_handle, hci.LinkPolicy.ENABLE_SNIFF_MODE
    )
    await self.enter_sniff_mode(acl_connection_handle)
    await self.write_link_policy_settings(acl_connection_handle, 0x0000)

    new_t_sniff = 0x0040
    await self.send_sniff_mode(acl_connection_handle, new_t_sniff)

    controller.send_ll(
        ll.SniffRsp(
            source_address=peer_address,
            destination_address=controller.address,
            status=ErrorCode.SUCCESS,
            interval=new_t_sniff,
        ),
        phy=Phy.BrEdr,
    )

    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.SNIFF,
            interval=new_t_sniff,
        )
    )

  # When the peer rejects a re-negotiation of the sniff interval, the
  # connection remains in Sniff mode with the previous interval.
  async def test_sniff_mode_renegotiation_rejected_by_peer(self):
    controller = self.controller
    peer_address = self.peer_address
    acl_connection_handle = await self.establish_acl_connection_peripheral()
    await self.write_link_policy_settings(
        acl_connection_handle, hci.LinkPolicy.ENABLE_SNIFF_MODE
    )
    await self.enter_sniff_mode(acl_connection_handle)

    new_t_sniff = 0x0040
    await self.send_sniff_mode(acl_connection_handle, new_t_sniff)

    controller.send_ll(
        ll.SniffRsp(
            source_address=peer_address,
            destination_address=controller.address,
            status=ErrorCode.UNSUPPORTED_LMP_OR_LL_PARAMETER,
            interval=0,
        ),
        phy=Phy.BrEdr,
    )

    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.UNSUPPORTED_LMP_OR_LL_PARAMETER,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.SNIFF,
            interval=self.t_sniff,
        )
    )

  # The peer can re-negotiate the sniff interval while already in Sniff
  # mode, even if Sniff mode was since disabled in the link policy.
  async def test_peer_sniff_request_renegotiation(self):
    controller = self.controller
    peer_address = self.peer_address
    acl_connection_handle = await self.establish_acl_connection_peripheral()
    await self.write_link_policy_settings(
        acl_connection_handle, hci.LinkPolicy.ENABLE_SNIFF_MODE
    )
    await self.enter_sniff_mode(acl_connection_handle)
    await self.write_link_policy_settings(acl_connection_handle, 0x0000)

    new_t_sniff = 0x0040

    controller.send_ll(
        ll.SniffReq(
            source_address=peer_address,
            destination_address=controller.address,
            timing_control_flags=0x00,
            d_sniff=new_t_sniff - 2,
            t_sniff=new_t_sniff,
            sniff_attempt=self.sniff_attempt,
            sniff_timeout=self.sniff_timeout,
        ),
        phy=Phy.BrEdr,
    )

    await self.expect_ll(
        ll.SniffRsp(
            source_address=controller.address,
            destination_address=peer_address,
            status=ErrorCode.SUCCESS,
            interval=new_t_sniff,
        )
    )

    await self.expect_evt(
        hci.ModeChange(
            status=ErrorCode.SUCCESS,
            connection_handle=acl_connection_handle,
            current_mode=hci.Mode.SNIFF,
            interval=new_t_sniff,
        )
    )

  # A Role Switch is rejected while the connection is in Sniff mode
  # (Vol 4, Part E § 7.2.8), and accepted again once Sniff mode is exited.
  async def test_role_switch_rejected_in_sniff_mode(self):
    controller = self.controller
    peer_address = self.peer_address
    acl_connection_handle = await self.establish_acl_connection_peripheral()
    await self.write_link_policy_settings(
        acl_connection_handle,
        hci.LinkPolicy.ENABLE_SNIFF_MODE | hci.LinkPolicy.ENABLE_ROLE_SWITCH,
    )
    await self.enter_sniff_mode(acl_connection_handle)

    controller.send_cmd(
        hci.SwitchRole(bd_addr=peer_address, role=hci.Role.CENTRAL)
    )

    await self.expect_evt(
        hci.SwitchRoleStatus(
            status=ErrorCode.COMMAND_DISALLOWED, num_hci_command_packets=1
        )
    )

    controller.send_ll(
        ll.UnsniffReq(
            source_address=peer_address,
            destination_address=controller.address,
        ),
        phy=Phy.BrEdr,
    )

    await self.expect_ll(
        ll.UnsniffRsp(
            source_address=controller.address,
            destination_address=peer_address,
            status=ErrorCode.SUCCESS,
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

    controller.send_cmd(
        hci.SwitchRole(bd_addr=peer_address, role=hci.Role.CENTRAL)
    )

    await self.expect_evt(
        hci.SwitchRoleStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    await self.expect_ll(
        ll.RoleSwitchRequest(
            source_address=controller.address, destination_address=peer_address
        )
    )
