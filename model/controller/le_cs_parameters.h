/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include <array>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "model/controller/controller_properties.h"
#include "packets/hci_packets.h"

namespace rootcanal {

//
// Channel Sounding configuration and settings.
//

struct LeCsDefaultSettings {
  uint8_t role_enable{};
  uint8_t cs_sync_antenna_selection{
          static_cast<uint8_t>(bluetooth::hci::CsSyncAntennaSelection::ANTENNA_1)};
  int8_t max_tx_power{20};
};

struct LeCsConfig {
  uint8_t config_id;
  std::array<uint8_t, 10> channel_map;
  uint8_t channel_map_repetition;
  uint8_t main_mode_type;
  uint8_t sub_mode_type;
  uint8_t min_main_mode_steps;
  uint8_t max_main_mode_steps;
  uint8_t main_mode_repetition;
  uint8_t mode_0_steps;
  uint8_t cs_sync_phy;
  uint8_t rtt_type;
  uint8_t role;
  uint8_t channel_selection_type;
  uint8_t ch3c_shape;
  uint8_t ch3c_jump;
};

struct LeCsParameters {
  std::optional<CsLocalSupportedCapabilities> remote_cs_capabilities;
  std::optional<std::array<uint8_t, 72>> remote_fae_table;
  LeCsDefaultSettings default_settings;
  std::unordered_map<uint8_t, LeCsConfig> config_map;

  // CS Security
  bool security_enabled{};
  uint64_t iv{};
  uint32_t in{};
  uint64_t pv{};
};

}  // namespace rootcanal
