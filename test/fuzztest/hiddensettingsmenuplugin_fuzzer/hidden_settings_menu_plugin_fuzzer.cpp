/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hidden_settings_menu_plugin_fuzzer.h"

#include "common_fuzzer.h"
#define protected public
#define private public
#include "hidden_settings_menu_plugin.h"
#undef protected
#undef private
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 24;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_SIZE) {
        return 0;
    }
    int32_t stringSize = size / 3;
    int32_t pos = 0;
    HiddenSettingsMenuPlugin plugin;
    MessageParcel installParcel;
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string policyData = CommonFuzzer::GetString(data, pos, stringSize, size);
    int32_t accountId = CommonFuzzer::GetU32Data(data);
    plugin.GetOthersMergePolicyData(adminName, accountId, policyData);
    return 0;
}
} // namespace EDM
} // namespace OHOS