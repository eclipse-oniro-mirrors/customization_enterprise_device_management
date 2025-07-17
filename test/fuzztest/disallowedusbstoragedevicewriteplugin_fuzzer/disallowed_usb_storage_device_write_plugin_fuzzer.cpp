/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "disallowed_usb_storage_device_write_plugin_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "disallowed_usb_storage_device_write_plugin.h"
#undef protected
#undef private
#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 128;

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }

    DisallowedUsbStorageDeviceWritePlugin plugin;
    bool policy = CommonFuzzer::GetU32Data(data) % 2;
    bool currentData = CommonFuzzer::GetU32Data(data) % 2;
    bool mergeData = CommonFuzzer::GetU32Data(data) % 2;
    int32_t userId = CommonFuzzer::GetU32Data(data);
    int32_t pos = 0;
    int32_t stringSize = size / 6;
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);

    plugin.OnSetPolicy(policy, currentData, mergeData, userId);
    plugin.OnAdminRemove(adminName, policy, mergeData, userId);
    plugin.SetUsbStorageDeviceWritePolicy(policy, userId);
    return 0;
}
} // namespace EDM
} // namespace OHOS