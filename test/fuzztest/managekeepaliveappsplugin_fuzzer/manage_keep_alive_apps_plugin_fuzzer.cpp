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

void DoSometingTest(const uint8_t* data, size_t size, int32_t pos, int32_t stringSize)
{
    ManageKeepAliveAppsPlugin plugin;
    uint32_t code = CommonFuzzer::GetU32Data(data);
    std::string policyData = CommonFuzzer::GetString(data, pos, stringSize, size);
    MessageParcel requestData;
    requestData.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
    MessageParcel reply;
    int32_t userId = CommonFuzzer::GetU32Data(data);
    std::string fuzzString(reinterpret_cast<const char*>(data), size);
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
    int32_t stringSize = (size - pos) / 9;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(HAS_USERID);
        int32_t userId = CommonFuzzer::GetU32Data(data);
        parcel.WriteInt32(userId);
        if (operateType == static_cast<uint32_t>(FuncOperateType::SET)) {
            parcel.WriteParcelable(&admin);
            parcel.WriteString("");
            std::vector<std::string> keepAliveAppsString;
            std::string bundleName(reinterpret_cast<const char*>(data), size / 2);
            keepAliveAppsString.push_back(bundleName);
            parcel.WriteStringVector(keepAliveAppsString);
            parcel.WriteBool(true);
        } else if (operateType == static_cast<uint32_t>(FuncOperateType::REMOVE)) {
            parcel.WriteParcelable(&admin);
            parcel.WriteString("");
            std::vector<std::string> keepAliveAppsString;
            std::string bundleName(reinterpret_cast<const char*>(data), size / 2);
            keepAliveAppsString.push_back(bundleName);
            parcel.WriteStringVector(keepAliveAppsString);
        } else {
            parcel.WriteString("");
            parcel.WriteInt32(1);
            parcel.WriteParcelable(&admin);
            parcel.WriteString(EdmConstants::KeepAlive::GET_MANAGE_KEEP_ALIVE_APPS_BUNDLE_NAME);
        }
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }
    DoSometingTest(data, size, pos, stringSize);
    return 0;
}
} // namespace EDM
} // namespace OHOS