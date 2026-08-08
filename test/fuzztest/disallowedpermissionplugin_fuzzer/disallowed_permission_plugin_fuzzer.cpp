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

#include "disallowed_permission_plugin_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "disallowed_permission_plugin.h"
#undef protected
#undef private
#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "enterprise_device_mgr_proxy.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 24;
constexpr int32_t USER_ID = 100;

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
    int32_t stringSize = size / 13;

    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = POLICY_FUNC_CODE(operateType, EdmInterfaceCode::DISALLOWED_PERMISSION);
        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(HAS_USERID);
        parcel.WriteInt32(USER_ID);
        if (operateType == static_cast<uint32_t>(FuncOperateType::GET)) {
            parcel.WriteString(WITHOUT_PERMISSION_TAG);
            parcel.WriteInt32(0);
            parcel.WriteParcelable(&admin);
        } else {
            parcel.WriteParcelable(&admin);
            parcel.WriteString(WITHOUT_PERMISSION_TAG);
            std::vector<std::string> permissions;
            permissions.push_back(CommonFuzzer::GetString(data, pos, stringSize, size));
            permissions.push_back(CommonFuzzer::GetString(data, pos, stringSize, size));
            parcel.WriteStringVector(permissions);
        }
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }

    DisallowedPermissionPlugin plugin;
    int32_t userId = CommonFuzzer::GetU32Data(data, pos, size);
    std::vector<std::string> permissions;
    permissions.push_back(CommonFuzzer::GetString(data, pos, stringSize, size));
    std::vector<std::string> failedData;
    plugin.SetOtherModulePolicy(permissions, userId, failedData);
    plugin.RemoveOtherModulePolicy(permissions, userId, failedData);
    return 0;
}
} // namespace EDM
} // namespace OHOS
