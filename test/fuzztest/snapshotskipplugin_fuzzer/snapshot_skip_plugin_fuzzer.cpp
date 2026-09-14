/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "snapshot_skip_plugin_fuzzer.h"

#include <system_ability_definition.h>

#define private public
#include "snapshot_skip_plugin.h"
#undef private
#include "array_string_serializer.h"
#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 28;
constexpr size_t STRING_COUNT = 13;
constexpr size_t INT32_COUNT = 2;
constexpr int32_t HAS_USERID = 1;
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
    int32_t stringSize = (size - sizeof(int32_t) * INT32_COUNT) / STRING_COUNT;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::SNAPSHOT_SKIP;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(HAS_USERID);
        parcel.WriteInt32(USER_ID);
        if (operateType) {
            parcel.WriteParcelable(&admin);
            std::vector<std::string> bundles;
            bundles.push_back(CommonFuzzer::GetString(data, pos, stringSize, size));
            parcel.WriteStringVector(bundles);
        } else {
            parcel.WriteInt32(0);
            parcel.WriteParcelable(&admin);
        }
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }

    SnapshotSkipPlugin plugin;
    std::vector<std::string> bundles = { CommonFuzzer::GetString(data, pos, stringSize, size) };
    std::vector<std::string> currentData = { CommonFuzzer::GetString(data, pos, stringSize, size) };
    std::vector<std::string> mergeData = { CommonFuzzer::GetString(data, pos, stringSize, size) };
    int32_t userId = CommonFuzzer::GetU32Data(data);
    plugin.OnSetPolicy(bundles, currentData, mergeData, userId);
    plugin.OnRemovePolicy(bundles, currentData, mergeData, userId);
    
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    plugin.OnAdminRemove(adminName, currentData, mergeData, userId);

    int32_t systemAbilityId = CommonFuzzer::GetU32Data(data, pos, size);
    plugin.OnOtherServiceStart(systemAbilityId);
    return 0;
}
} // namespace EDM
} // namespace OHOS