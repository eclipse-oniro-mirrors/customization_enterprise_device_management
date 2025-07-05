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

#include "disable_usb_plugin_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "disable_usb_plugin.h"
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
constexpr size_t MIN_SIZE = 3;

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }

    DisableUsbPlugin plugin;
    int32_t userId = CommonFuzzer::GetU32Data(data);
    bool status = CommonFuzzer::GetU32Data(data) % 2;
    plugin.SetOtherModulePolicy(status, userId);
    bool hasConflict = false;
    plugin.HasConflictPolicy(hasConflict);
    plugin.RemoveOtherModulePolicy(userId);
    return 0;
}
} // namespace EDM
} // namespace OHOS