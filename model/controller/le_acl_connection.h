/*
 * Copyright (C) 2025 The Android Open Source Project
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

#pragma once

#include <chrono>
#include <cstdint>

#include "hci/address_with_type.h"
#include "packets/hci_packets.h"

namespace rootcanal {

using bluetooth::hci::AddressWithType;

// Model the LE connection of a device to the controller.
class LeAclConnection final {
public:
  const uint16_t handle;
  const AddressWithType address;
  const AddressWithType own_address;
  const AddressWithType resolved_address;
  const bluetooth::hci::Role role;

  LeAclConnection(uint16_t handle, AddressWithType address, AddressWithType own_address,
                  AddressWithType resolved_address, bluetooth::hci::Role role);
  ~LeAclConnection() = default;

  void Encrypt();
  bool IsEncrypted() const;

  int8_t GetRssi() const;
  void SetRssi(int8_t rssi);

  std::chrono::steady_clock::duration TimeUntilNearExpiring() const;
  std::chrono::steady_clock::duration TimeUntilExpired() const;
  void ResetLinkTimer();
  bool IsNearExpiring() const;
  bool HasExpired() const;

  // LE-ACL state.
  void InitiatePhyUpdate() { initiated_phy_update_ = true; }
  void PhyUpdateComplete() { initiated_phy_update_ = false; }
  bool InitiatedPhyUpdate() const { return initiated_phy_update_; }
  bluetooth::hci::PhyType GetTxPhy() const { return tx_phy_; }
  bluetooth::hci::PhyType GetRxPhy() const { return rx_phy_; }
  void SetTxPhy(bluetooth::hci::PhyType phy) { tx_phy_ = phy; }
  void SetRxPhy(bluetooth::hci::PhyType phy) { rx_phy_ = phy; }

private:
  // Reports the RSSI measured for the last packet received on
  // this connection.
  int8_t rssi_{0};

  // State variables
  bool encrypted_{false};
  std::chrono::steady_clock::time_point last_packet_timestamp_;
  std::chrono::steady_clock::duration timeout_;

  // LE-ACL state.
  bluetooth::hci::PhyType tx_phy_{bluetooth::hci::PhyType::LE_1M};
  bluetooth::hci::PhyType rx_phy_{bluetooth::hci::PhyType::LE_1M};
  bool initiated_phy_update_{false};
};

}  // namespace rootcanal
