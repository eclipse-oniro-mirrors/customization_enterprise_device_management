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

#include "managed_browser_policy_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "cJSON.h"
#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "handle_policy_data.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "utils.h"
#define private public
#include "managed_browser_policy_plugin.h"
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 32;
constexpr size_t WITHOUT_USERID = 0;

void SetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size, AppExecFwk::ElementName admin)
{
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    int32_t pos = 0;
    int32_t stringSize = size / 4;
    std::string bundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string policyName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string policyValue = CommonFuzzer::GetString(data, pos, stringSize, size);
    parcel.WriteString(bundleName);
    parcel.WriteString(policyName);
    parcel.WriteString(policyValue);
}

void SetGetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size, AppExecFwk::ElementName admin)
{
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    int32_t pos = 0;
    int32_t stringSize = size / 4;
    int32_t typeSelect = CommonFuzzer::GetU32Data(data, pos, size) % 3;
    if (typeSelect == 0) {
        parcel.WriteString(EdmConstants::Browser::GET_MANAGED_BROWSER_VERSION);
        std::string bundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
        parcel.WriteString(bundleName);
    } else if (typeSelect == 1) {
        parcel.WriteString(EdmConstants::Browser::GET_MANAGED_BROWSER_FILE_DATA);
        std::string bundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
        parcel.WriteString(bundleName);
    } else {
        parcel.WriteString(EdmConstants::Browser::GET_SELF_MANAGED_BROWSER_FILE_DATA);
    }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }
    int32_t pos = 0;
    int32_t stringSize = size / 4;
    
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::SET);
        operateType <= static_cast<uint32_t>(FuncOperateType::GET); operateType++) {
        uint32_t code = EdmInterfaceCode::MANAGED_BROWSER_POLICY;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        
        if (operateType == static_cast<uint32_t>(FuncOperateType::GET)) {
            SetGetParcelContent(parcel, data, size, admin);
        } else {
            SetParcelContent(parcel, data, size, admin);
        }

        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }

    ManagedBrowserPolicyPlugin plugin;
    std::string fuzzString(reinterpret_cast<const char*>(data), size);
    std::string bundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string policyName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string policyValue = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    int32_t userId = CommonFuzzer::GetU32Data(data, pos, size);
    bool isGlobalChanged = CommonFuzzer::GetU32Data(data, pos, size) % 2;
    
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    HandlePolicyData handlePolicyData;
    handlePolicyData.policyData = fuzzString;
    handlePolicyData.mergePolicyData = fuzzString;
    handlePolicyData.isChanged = isGlobalChanged;
    
    plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, bundleName, policyName, policyValue);
    plugin.OnHandlePolicyDone(0, adminName, isGlobalChanged, userId);
    plugin.OnAdminRemove(adminName, fuzzString, fuzzString, userId);
    
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    plugin.OnGetPolicy(fuzzString, dataParcel, replyParcel, userId);

    return 0;
}
} // namespace EDM
} // namespace OHOS
