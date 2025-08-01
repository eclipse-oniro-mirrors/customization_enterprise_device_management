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

#include "allowed_app_distribution_types_plugin_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "allowed_app_distribution_types_plugin.h"
#undef protected
#undef private
#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "get_data_template.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "plugin_manager.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 12;
constexpr int32_t WITHOUT_USERID = 0;

extern "C" int LLVMFuzzerInitialize(const uint8_t* data, size_t size)
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
    int32_t stringSize = size / 7;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(WITHOUT_USERID);
        if (operateType) {
            parcel.WriteParcelable(&admin);
            std::vector<int32_t> appDistributionTypes;
            appDistributionTypes.push_back(CommonFuzzer::GetU32Data(data));
            parcel.WriteInt32Vector(appDistributionTypes);
        } else {
            parcel.WriteString("");
            parcel.WriteInt32(0);
            parcel.WriteParcelable(&admin);
        }
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }

    AllowedAppDistributionTypesPlugin plugin;
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    int32_t intPos = 0;
    std::vector<int32_t> policyData;
    policyData.push_back(CommonFuzzer::GetU32Data(data, intPos, size));
    std::vector<int32_t> mergeData;
    mergeData.push_back(CommonFuzzer::GetU32Data(data, intPos, size));
    int32_t userId = CommonFuzzer::GetU32Data(data, intPos, size);
    plugin.OnAdminRemove(adminName, policyData, mergeData, userId);
    return 0;
}
} // namespace EDM
} // namespace OHOS