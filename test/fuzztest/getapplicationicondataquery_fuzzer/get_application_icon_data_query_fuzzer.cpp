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

#include "get_application_icon_data_query_fuzzer.h"

#include <string>

#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "enterprise_device_mgr_proxy.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 10;

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
    uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
    uint32_t code = EdmInterfaceCode::GET_APPLICATION_ICON_DATA;
    code = POLICY_FUNC_CODE_NEW(operateType, code);

    // The parcel layout must be identical to ApplicationManagerAddon::GetApplicationIconData:
    // default userId, QueryPolicy::ALL and bundleName.
    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(EdmConstants::DEFAULT_USER_ID);
    parcel.WriteInt32(static_cast<int32_t>(QueryPolicy::ALL));
    std::string bundleName(reinterpret_cast<const char*>(data), size / 2);
    parcel.WriteString(bundleName);

    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    return 0;
}
} // namespace EDM
} // namespace OHOS
