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

#include "disallow_mobile_data_plugin_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "disallow_mobile_data_plugin.h"
#undef protected
#undef private
#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "handle_policy_data.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 16;
constexpr size_t WITHOUT_USERID = 0;

extern "C" int LLVMFuzzerInitialize(const uint8_t* data, size_t size)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

void DoSomethingInterestingWithAPI(const uint8_t* data, size_t size, int32_t pos, int32_t stringSize)
{
    DisallowMobileDataPlugin plugin;
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string policyData = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string mergeData = CommonFuzzer::GetString(data, pos, stringSize, size);
    int32_t userId = CommonFuzzer::GetU32Data(data);
    plugin.OnAdminRemove(adminName, policyData, mergeData, userId);
    MessageParcel parcel;
    int32_t forceOpen = CommonFuzzer::GetU32Data(data);
    parcel.WriteInt32(forceOpen);
    plugin.OnHandleForceOpen(parcel);

    MessageParcel setParcel;
    MessageParcel replyParcel;
    uint32_t code = EdmInterfaceCode::DISALLOWED_MOBILE_DATA;
    code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET), code);
    setParcel.WriteString(EdmConstants::MobileData::DISALLOW_FLAG);
    bool isDisallow = CommonFuzzer::GetU32Data(data) % 2;
    setParcel.WriteBool(isDisallow);
    HandlePolicyData handlePolicyData;
    plugin.OnHandlePolicy(code, setParcel, replyParcel, handlePolicyData, userId);
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
    int32_t stringSize = size / 15;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::DISALLOWED_MOBILE_DATA;
        code = POLICY_FUNC_CODE(operateType, code);
        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(WITHOUT_USERID);
        if (operateType) {
            parcel.WriteParcelable(&admin);
            std::vector<std::string> key {CommonFuzzer::GetString(data, pos, stringSize, size)};
            std::vector<std::string> value {CommonFuzzer::GetString(data, pos, stringSize, size)};
            parcel.WriteStringVector(key);
            parcel.WriteStringVector(value);
        } else {
            parcel.WriteString("");
            bool hasAdmin = CommonFuzzer::GetU32Data(data) % 2;
            if (hasAdmin) {
                parcel.WriteInt32(0);
                parcel.WriteParcelable(&admin);
            } else {
                parcel.WriteInt32(0);
            }
            parcel.WriteInt32(CommonFuzzer::GetU32Data(data));
        }
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }
    DoSomethingInterestingWithAPI(data, size, pos, stringSize);
    return 0;
}
} // namespace EDM
} // namespace OHOS