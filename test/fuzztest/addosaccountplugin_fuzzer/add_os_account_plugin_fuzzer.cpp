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

#include "add_os_account_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 4;
constexpr int32_t WITHOUT_USERID = 0;

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
    int32_t stringSize = size / 4;

    uint32_t code = EdmInterfaceCode::ADD_OS_ACCOUNT;
    code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET), code);

    AppExecFwk::ElementName admin;
    admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
    admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    std::vector<std::string> key {CommonFuzzer::GetString(data, pos, stringSize, size)};
    std::vector<std::string> value {CommonFuzzer::GetString(data, pos, stringSize, size)};
    parcel.WriteStringVector(key);
    parcel.WriteStringVector(value);

    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    return 0;
}
} // namespace EDM
} // namespace OHOS