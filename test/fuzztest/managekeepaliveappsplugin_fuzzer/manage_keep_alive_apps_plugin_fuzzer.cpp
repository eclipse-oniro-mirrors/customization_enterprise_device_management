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
#include "common_fuzzer.h"
#include "cJSON.h"
#define protected public
#define private public
#include "manage_keep_alive_apps_plugin.h"
#undef protected
#undef private
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "manage_keep_alive_apps_info.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 14;
constexpr int32_t EVEN_NUMBER = 2;
constexpr size_t BOOL_BUM = 4;
constexpr size_t STRING_BUM = 6;

std::string InitKeepAlivePolicies(const uint8_t* data, size_t size, int32_t& pos, size_t stringSize)
{
    cJSON* keepAlivePolicies = cJSON_CreateObject();
    if (!keepAlivePolicies) {
        return "";
    }
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        cJSON_Delete(keepAlivePolicies);
        return "";
    }
    cJSON_AddItemToObject(root, "bundleName",
        cJSON_CreateString(CommonFuzzer::GetString(data, pos, stringSize, size).c_str()));
    cJSON_AddItemToObject(root, "disallowModify", cJSON_CreateBool(CommonFuzzer::GetBool(data, pos, size)));
    cJSON* keepAliveArray = cJSON_CreateArray();
    if (!keepAliveArray) {
        cJSON_Delete(keepAlivePolicies);
        cJSON_Delete(root);
        return "";
    }
    if (!cJSON_AddItemToArray(keepAlivePolicies, root)) {
        cJSON_Delete(keepAlivePolicies);
        cJSON_Delete(root);
        return "";
    }
    char* buffer = cJSON_PrintUnformatted(keepAlivePolicies);
    if (buffer == nullptr) {
        cJSON_Delete(keepAlivePolicies);
        return "";
    }
    std::string json(buffer);
    cJSON_free(buffer);
    cJSON_Delete(keepAlivePolicies);
    return json;
}

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
    int32_t stringSize = (size - BOOL_BUM) / STRING_BUM;
    ManageKeepAliveAppsPlugin plugin;
    uint32_t code = CommonFuzzer::GetU32Data(data);
    MessageParcel requestData;
    requestData.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
    MessageParcel reply;
    int32_t userId = CommonFuzzer::GetU32Data(data);
    std::string fuzzString = InitKeepAlivePolicies(data, size, pos, stringSize);
    std::string mergeFuzzString = InitKeepAlivePolicies(data, size, pos, stringSize);
    std::string currentPolicies = InitKeepAlivePolicies(data, size, pos, stringSize);
    std::string mergePolicies = InitKeepAlivePolicies(data, size, pos, stringSize);
    HandlePolicyData handlePolicyData;
    handlePolicyData.policyData = fuzzString;
    handlePolicyData.mergePolicyData = mergeFuzzString;
    handlePolicyData.isChanged = CommonFuzzer::GetU32Data(data) % EVEN_NUMBER;
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    plugin.OnHandlePolicy(code, requestData, reply, handlePolicyData, userId);
    plugin.OnGetPolicy(fuzzString, requestData, reply, userId);
    plugin.OnAdminRemove(adminName, currentPolicies, mergePolicies, userId);
    return 0;
}
} // namespace EDM
} // namespace OHOS