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
 
#include "install_local_enterprise_app_enabled_plugin_fuzzer.h"
 
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
constexpr const char *WITHOUT_PERMISSION_TAG = "";

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
    int32_t stringSize = size / 15;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::SET); operateType++) {
        uint32_t code = EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED;
        code = POLICY_FUNC_CODE(operateType, code);
 
        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(WITHOUT_USERID);
        if (operateType == static_cast<uint32_t>(FuncOperateType::SET)) {
            parcel.WriteParcelable(&admin);
            parcel.WriteString(WITHOUT_PERMISSION_TAG);
            std::vector<std::string> keepAliveAppsString;
            std::string bundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
            keepAliveAppsString.push_back(bundleName);
            parcel.WriteStringVector(keepAliveAppsString);
            parcel.WriteBool(true);
        } else {
            parcel.WriteString(WITHOUT_PERMISSION_TAG);
            parcel.WriteInt32(1);
            parcel.WriteParcelable(&admin);
        }
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }
    return 0;
}
} // namespace EDM
} // namespace OHOS