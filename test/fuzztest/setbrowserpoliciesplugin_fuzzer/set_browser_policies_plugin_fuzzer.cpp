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

#include "set_browser_policies_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 16;
constexpr size_t WITHOUT_USERID = 0;
constexpr int32_t HAS_ADMIN = 0;
constexpr int32_t WITHOUT_ADMIN = 1;

void SetParcelContent(MessageParcel &parcel, uint32_t operateType,
    const uint8_t* data, size_t size, AppExecFwk::ElementName admin)
{
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    if (operateType) {
        parcel.WriteParcelable(&admin);
        bool isSetAll = CommonFuzzer::GetU32Data(data) % 2;
        int32_t pos = 0;
        int32_t stringSize = size / 3;
        std::string appId(CommonFuzzer::GetString(data, pos, stringSize, size));
        std::string policies(CommonFuzzer::GetString(data, pos, stringSize, size));
        if (isSetAll) {
            std::vector<std::string> appIds;
            std::vector<std::string> policiesList;
            appIds.push_back(appId);
            policiesList.push_back(policies);
            parcel.WriteStringVector(appIds);
            parcel.WriteStringVector(policiesList);
        } else {
            parcel.WriteString("");
            std::string policyName(CommonFuzzer::GetString(data, pos, stringSize, size));
            std::vector<std::string> params;
            params.push_back(appId);
            params.push_back(policyName);
            params.push_back(policies);
            parcel.WriteStringVector(params);
        }
    } else {
        parcel.WriteString("");
        bool hasAdmin = CommonFuzzer::GetU32Data(data) % 2;
        if (hasAdmin) {
            parcel.WriteInt32(HAS_ADMIN);
            parcel.WriteParcelable(&admin);
        } else {
            parcel.WriteInt32(WITHOUT_ADMIN);
        }
        std::string appId(reinterpret_cast<const char*>(data), size);
        parcel.WriteString(appId);
    }
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
    int32_t stringSize = (size - pos) / 6;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::SET_BROWSER_POLICIES;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        SetParcelContent(parcel, operateType, data, size, admin);

        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }
    return 0;
}
} // namespace EDM
} // namespace OHOS