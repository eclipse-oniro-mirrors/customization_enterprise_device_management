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

#include "get_installed_bundle_storage_stats_query_fuzzer.h"

#include <system_ability_definition.h>

#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#define private public
#include "get_installed_bundle_storage_stats_query.h"
#undef private
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 24;
constexpr int32_t HAS_USERID = 1;
constexpr int32_t HAS_ADMIN = 1;

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
    int32_t stringSize = size / 8;

    uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
    uint32_t code = EdmInterfaceCode::GET_BUNDLE_STORAGE_STATS;
    code = POLICY_FUNC_CODE(operateType, code);

    AppExecFwk::ElementName admin;
    admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
    admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(HAS_USERID);
    parcel.WriteInt32(EdmConstants::DEFAULT_USER_ID);
    parcel.WriteString(EdmConstants::PERMISSION_TAG_VERSION_23);
    parcel.WriteInt32(HAS_ADMIN);
    parcel.WriteParcelable(&admin);

    std::vector<std::string> bundleNames;
    std::string bundleName(reinterpret_cast<const char*>(data), size / 2);
    bundleNames.emplace_back(bundleName);
    parcel.WriteUint32(bundleNames.size());
    parcel.WriteStringVector(bundleNames);
    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    return 0;
}
} // namespace EDM
} // namespace OHOS