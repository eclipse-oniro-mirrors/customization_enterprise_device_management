/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "location_policy_plugin_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "location_policy_plugin.h"
#undef protected
#undef private
#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"
#include "location_policy.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 5;

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }
    int32_t stringSize = size / 2;
    int32_t pos = 0;

    LocationPolicyPlugin plugin;
    int32_t currentData = CommonFuzzer::GetU32Data(data);
    int32_t mergeData = static_cast<int32_t>(LocationPolicy::DEFAULT_LOCATION_SERVICE);
    int32_t userId = CommonFuzzer::GetU32Data(data);
    int32_t policyData = CommonFuzzer::GetU32Data(data);
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);

    int32_t status = static_cast<int32_t>(LocationPolicy::DEFAULT_LOCATION_SERVICE);
    plugin.OnSetPolicy(status, currentData, mergeData, userId);
    status = static_cast<int32_t>(LocationPolicy::DISALLOW_LOCATION_SERVICE);
    plugin.OnSetPolicy(status, currentData, mergeData, userId);
    status = static_cast<int32_t>(LocationPolicy::FORCE_OPEN_LOCATION_SERVICE);
    plugin.OnSetPolicy(status, currentData, mergeData, userId);
    plugin.SetDefaultLocationPolicy();
    plugin.OnAdminRemove(adminName, policyData, mergeData, userId);
    return 0;
}
} // namespace EDM
} // namespace OHOS