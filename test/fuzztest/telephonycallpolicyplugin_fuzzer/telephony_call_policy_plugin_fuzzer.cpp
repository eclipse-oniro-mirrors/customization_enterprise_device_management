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

#include "telephony_call_policy_plugin_fuzzer.h"
#include <system_ability_definition.h>

#define protected public
#define private public
#include "telephony_call_policy_plugin.h"
#undef protected
#undef private
#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "get_data_template.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "plugin_manager.h"
#include "usb_device_id.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 24;
constexpr int32_t WITHOUT_USERID = 0;

void CheckPrivateFunction(const uint8_t* data, const size_t size, int32_t &pos)
{
    int32_t stringSize = size / 18;
    int32_t policyFlag = size % 3;
    TelephonyCallPolicyPlugin plugin;
    std::vector<std::string> v1 {CommonFuzzer::GetString(data, pos, stringSize, size)};
    std::vector<std::string> v2 {CommonFuzzer::GetString(data, pos, stringSize, size)};
    plugin.MergeAndRemoveDuplicates(v1, v2);
    TelephonyCallPolicyType info1 {v1, policyFlag};
    TelephonyCallPolicyType info2 {v2, policyFlag};
    std::string key = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::map<std::string, TelephonyCallPolicyType> dataMap1 = {{key, info1}};
    std::map<std::string, TelephonyCallPolicyType> dataMap2 = {{key, info2}};
    int32_t flag = CommonFuzzer::GetU32Data(data);
    plugin.IsTrustBlockConflict(key, flag, dataMap1);
    plugin.CheckIsLimit(key, flag, v2, dataMap1);
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string policyData = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string mergeData = CommonFuzzer::GetString(data, pos, stringSize, size);
    int32_t userId = CommonFuzzer::GetU32Data(data);
    plugin.AddCurrentAndMergePolicy(dataMap1, dataMap2, key, flag, v1);
    plugin.RemoveCurrentAndMergePolicy(dataMap1, dataMap2, key, flag, v1);
    int32_t userId100 = 100;
    plugin.GetOthersMergePolicyData(adminName, userId100, policyData);
    plugin.OnAdminRemove(adminName, policyData, mergeData, userId);
    plugin.OnOtherServiceStart(userId);
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
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
    int32_t stringSize = size / 18;
    int32_t policyFlag = size % 3;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::DISALLOWED_SIM;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        std::string callType = CommonFuzzer::GetString(data, pos, stringSize, size);
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(WITHOUT_USERID);
        if (operateType) {
            parcel.WriteParcelable(&admin);
            parcel.WriteString("");
            parcel.WriteString(callType);
            parcel.WriteInt32(policyFlag);
            std::vector<std::string> numbers {CommonFuzzer::GetString(data, pos, stringSize, size)};
            parcel.WriteStringVector(numbers);
        } else {
            parcel.WriteString("");
            parcel.WriteInt32(0);
            parcel.WriteParcelable(&admin);
            parcel.WriteString(callType);
            parcel.WriteInt32(policyFlag);
        }
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }

    CheckPrivateFunction(data, size, pos);
    return 0;
}
} // namespace EDM
} // namespace OHOS