from dataclasses import dataclass
from rootcanal.packets import hci
from rootcanal.packets import ll
import unittest
from rootcanal.packets.hci import ErrorCode
from rootcanal.bluetooth import Address
from test.controller_test import ControllerTest
from rootcanal.controller import Phy


class Test(ControllerTest):
    # Verify that the controller can establish a connection if the remote device
    # is initiating a connection at the same time. The local device responds to he
    # page events and accepts the connection. The local connection attempt is
    # abandoned and a Connection Complete event with status Connection Already
    # Exists is sent to the Host.

    async def test_scenario_1(self):
        controller = self.controller
        peer_address = Address("11:22:33:44:55:66")

        controller.send_cmd(
            hci.WriteScanEnable(scan_enable=hci.ScanEnable.PAGE_SCAN_ONLY)
        )

        await self.expect_evt(
            hci.WriteScanEnableComplete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        controller.send_cmd(
            hci.CreateConnection(
                bd_addr=peer_address,
                packet_type=0,
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

        await self.expect_evt(
            hci.ConnectionComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=self.Any,
                bd_addr=peer_address,
                link_type=hci.LinkType.ACL,
                encryption_enabled=hci.Enable.DISABLED,
            )
        )

    # Verify that when both the local and remote devices initiate a BR/EDR page
    # simultaneously and the remote device responds to our page first (completing
    # the outgoing ACL connection before the local Host accepts the incoming
    # connection request), the controller rejects HCI_Accept_Connection_Request
    # with ErrorCode.CONNECTION_ALREADY_EXISTS and clears its pending page scan
    # state so the Host does not wait indefinitely for a second
    # HCI_Connection_Complete event.
    async def test_scenario_2(self):
        controller = self.controller
        peer_address = Address("11:22:33:44:55:66")

        controller.send_cmd(
            hci.WriteScanEnable(scan_enable=hci.ScanEnable.PAGE_SCAN_ONLY)
        )

        await self.expect_evt(
            hci.WriteScanEnableComplete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        controller.send_cmd(
            hci.CreateConnection(
                bd_addr=peer_address,
                packet_type=0,
                page_scan_repetition_mode=hci.PageScanRepetitionMode.R1,
                allow_role_switch=hci.CreateConnectionRoleSwitch.ALLOW_ROLE_SWITCH,
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
                allow_role_switch=True,
            )
        )

        controller.send_ll(
            ll.Page(
                source_address=peer_address,
                destination_address=controller.address,
                allow_role_switch=True,
            ),
            phy=Phy.BrEdr,
        )

        await self.expect_evt(
            hci.ConnectionRequest(
                bd_addr=peer_address, link_type=hci.ConnectionRequestLinkType.ACL
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

        controller.send_cmd(
            hci.AcceptConnectionRequest(
                bd_addr=peer_address,
                role=hci.AcceptConnectionRequestRole.REMAIN_PERIPHERAL,
            )
        )

        conn_complete = await self.expect_evt(
            hci.ConnectionComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=self.Any,
                bd_addr=peer_address,
                link_type=hci.LinkType.ACL,
                encryption_enabled=hci.Enable.DISABLED,
            )
        )

        # Because the ACL connection for peer_address was already established by
        # the peer's PageResponse, accepting the duplicate incoming connection
        # request returns CONNECTION_ALREADY_EXISTS so the Host immediately
        # clears its pending incoming connection state.
        await self.expect_evt(
            hci.AcceptConnectionRequestStatus(
                status=ErrorCode.CONNECTION_ALREADY_EXISTS,
                num_hci_command_packets=1,
            )
        )

        # Terminate the connection.
        controller.send_cmd(
            hci.Disconnect(
                connection_handle=conn_complete.connection_handle,
                reason=hci.DisconnectReason.REMOTE_USER_TERMINATED_CONNECTION,
            )
        )

        await self.expect_evt(
            hci.DisconnectStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1)
        )

        await self.expect_ll(
            ll.Disconnect(
                source_address=controller.address,
                destination_address=peer_address,
                reason=hci.DisconnectReason.REMOTE_USER_TERMINATED_CONNECTION,
            )
        )

        await self.expect_evt(
            hci.DisconnectionComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=conn_complete.connection_handle,
                reason=ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST,
            )
        )

        # Reconnect to the same peer address.
        # Verify that the pending page scan state was cleared during collision
        # resolution and subsequent CreateConnection commands are accepted without
        # returning CONNECTION_ALREADY_EXISTS.
        controller.send_cmd(
            hci.CreateConnection(
                bd_addr=peer_address,
                packet_type=0,
                page_scan_repetition_mode=hci.PageScanRepetitionMode.R1,
                allow_role_switch=hci.CreateConnectionRoleSwitch.ALLOW_ROLE_SWITCH,
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
                allow_role_switch=True,
            )
        )
