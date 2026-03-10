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

#include "set_allowed_kiosk_apps_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "array_string_serializer.h"
#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "utils.h"
#define private public
#include "set_allowed_kiosk_apps_plugin.h"
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 24;
constexpr size_t WITHOUT_USERID = 0;
constexpr int32_t STRING_NUMS = 4;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

void SetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size, AppExecFwk::ElementName admin)
{
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    int32_t pos = 0;
    int32_t stringSize = size / STRING_NUMS;
    std::vector<std::string> appIdentifiers;
    int32_t numApps = CommonFuzzer::GetU32Data(data, pos, size) % 250 + 1;
    for (int32_t i = 0; i < numApps && pos + stringSize < size; i++) {
        appIdentifiers.push_back(CommonFuzzer::GetString(data, pos, stringSize, size));
    }
    parcel.WriteStringVector(appIdentifiers);
}

void SetGetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size, AppExecFwk::ElementName admin)
{
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
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
    int32_t stringSize = size / STRING_NUMS;
    
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::SET);
        operateType <= static_cast<uint32_t>(FuncOperateType::GET); operateType++) {
        uint32_t code = EdmInterfaceCode::ALLOWED_KIOSK_APPS;
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

    SetAllowedKioskAppsPlugin plugin;
    std::vector<std::string> changedData;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    pos = 0;
    stringSize = size / STRING_NUMS;
    int32_t numApps = CommonFuzzer::GetU32Data(data, pos, size) % 250 + 1;
    for (int32_t i = 0; i < numApps && pos + stringSize < size; i++) {
        changedData.push_back(CommonFuzzer::GetString(data, pos, stringSize, size));
    }
    
    plugin.OnSetPolicy(changedData, currentData, mergeData, WITHOUT_USERID);
    
    std::string policyData;
    ArrayStringSerializer::GetInstance()->Serialize(changedData, policyData);
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    plugin.OnGetPolicy(policyData, dataParcel, replyParcel, WITHOUT_USERID);
    
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    plugin.OnAdminRemove(adminName, currentData, mergeData, WITHOUT_USERID);
    
    int32_t systemAbilityId = CommonFuzzer::GetU32Data(data, pos, size) % 1000;
    plugin.OnOtherServiceStart(systemAbilityId);

    return 0;
}
} // namespace EDM
} // namespace OHOS
