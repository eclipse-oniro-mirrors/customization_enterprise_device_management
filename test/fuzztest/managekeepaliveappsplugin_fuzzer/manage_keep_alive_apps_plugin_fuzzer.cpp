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

#include "manage_keep_alive_apps_plugin_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "manage_keep_alive_apps_plugin.h"
#undef protected
#undef private
#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "manage_keep_alive_apps_info.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 10;
constexpr int32_t HAS_USERID = 1;
constexpr int32_t EVEN_NUMBER = 2;

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }
    int32_t pos = 0;
    int32_t stringSize = (size - pos) / 9;
    ManageKeepAliveAppsPlugin plugin;
    uint32_t code = CommonFuzzer::GetU32Data(data);
    std::string policyData = CommonFuzzer::GetString(data, pos, stringSize, size);
    MessageParcel requestData;
    requestData.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
    MessageParcel reply;
    int32_t userId = CommonFuzzer::GetU32Data(data);
    std::string fuzzString = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string currentPolicies = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string mergePolicies = CommonFuzzer::GetString(data, pos, stringSize, size);
    HandlePolicyData handlePolicyData;
    handlePolicyData.policyData = fuzzString;
    handlePolicyData.mergePolicyData = fuzzString;
    handlePolicyData.isChanged = CommonFuzzer::GetU32Data(data) % EVEN_NUMBER;
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    plugin.OnHandlePolicy(code, requestData, reply, handlePolicyData, userId);
    plugin.OnGetPolicy(fuzzString, requestData, reply, userId);
    plugin.OnAdminRemove(adminName, currentPolicies, mergePolicies, userId);
    return 0;
}
} // namespace EDM
} // namespace OHOS