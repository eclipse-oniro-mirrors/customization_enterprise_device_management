/*
 * Copyright (c) (c) 2025 Huawei Device Co., Ltd.
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

#include "fingerprint_auth_plugin_fuzzer.h"

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
#include "fingerprint_auth_plugin.h"
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 32;
constexpr size_t WITHOUT_USERID = 0;

void SetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size,
    AppExecFwk::ElementName admin, bool isFingerprintType)
{
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    int32_t pos = 0;
    
    if (isFingerprintType) {
        parcel.WriteString(EdmConstants::FINGERPRINT_AUTH_TYPE);
    } else {
        parcel.WriteString(EdmConstants::DISALLOW_FOR_ACCOUNT_TYPE);
        int32_t accountId = CommonFuzzer::GetU32Data(data, pos, size);
        parcel.WriteInt32(accountId);
    }
    
    bool disallow = CommonFuzzer::GetU32Data(data, pos, size) % 2;
    parcel.WriteBool(disallow);
}

void SetGetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size, AppExecFwk::ElementName admin)
{
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    int32_t pos = 0;
    
    int32_t typeSelect = CommonFuzzer::GetU32Data(data, pos, size) % 2;
    if (typeSelect == 0) {
        parcel.WriteString(EdmConstants::FINGERPRINT_AUTH_TYPE);
    } else {
        parcel.WriteString(EdmConstants::DISALLOW_FOR_ACCOUNT_TYPE);
        int32_t accountId = CommonFuzzer::GetU32Data(data, pos, size);
        parcel.WriteInt32(accountId);
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
    int32_t stringSize = size / 8;
    
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::SET);
        operateType <= static_cast<uint32_t>(FuncOperateType::GET); operateType++) {
        uint32_t code = EdmInterfaceCode::FINGERPRINT_AUTH;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        
        if (operateType == static_cast<uint32_t>(FuncOperateType::GET)) {
            SetGetParcelContent(parcel, data, size, admin);
        } else {
            bool isFingerprintType = CommonFuzzer::GetU32Data(data, pos, size) % 2;
            SetParcelContent(parcel, data, size, admin, isFingerprintType);
        }

        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }

    FingerprintAuthPlugin plugin;
    std::string fuzzString(reinterpret_cast<const char*>(data), size);
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    int32_t userId = CommonFuzzer::GetU32Data(data, pos, size);
    bool isGlobalChanged = CommonFuzzer::GetU32Data(data, pos, size) % 2;
    
    HandlePolicyData handlePolicyData;
    handlePolicyData.policyData = fuzzString;
    handlePolicyData.mergePolicyData = fuzzString;
    handlePolicyData.isChanged = isGlobalChanged;
    
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    plugin.OnHandlePolicy(0, dataParcel, replyParcel, handlePolicyData, userId);
    plugin.OnHandlePolicyDone(0, adminName, isGlobalChanged, userId);
    plugin.OnAdminRemove(adminName, fuzzString, fuzzString, userId);
    
    std::string othersMergePolicyData;
    plugin.GetOthersMergePolicyData(adminName, userId, othersMergePolicyData);
    
    int32_t systemAbilityId = CommonFuzzer::GetU32Data(data, pos, size) % 1000;
    plugin.OnOtherServiceStart(systemAbilityId);

    return 0;
}
} // namespace EDM
} // namespace OHOS
