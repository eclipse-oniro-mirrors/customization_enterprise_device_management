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

#include "get_call_logs_plugin_fuzzer.h"

#include <string>
#include <system_ability_definition.h>

#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 24;
constexpr int32_t STRING_SIZE_DIVISOR = 20;

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

    uint32_t code = EdmInterfaceCode::GET_CALL_LOGS;
    code = POLICY_FUNC_CODE_NEW(static_cast<uint32_t>(FuncOperateType::GET), code);

    int32_t pos = 0;
    int32_t queryPolicy = CommonFuzzer::GetU32Data(data, pos, size);
    int64_t startTime = static_cast<int64_t>(CommonFuzzer::GetLong(data, pos, size));
    int64_t endTime = static_cast<int64_t>(CommonFuzzer::GetU32Data(data, pos, size));
    bool hasTelephoneNumber =
        (size > static_cast<size_t>(pos)) ? (data[pos] % BINARY_DECISION_DIVISOR != 0) : false;
    pos++;
    int32_t stringSize = static_cast<int32_t>(size / STRING_SIZE_DIVISOR);
    std::string telephoneNumber = CommonFuzzer::GetString(data, pos, stringSize, size);

    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(EdmConstants::DEFAULT_USER_ID);
    parcel.WriteInt32(queryPolicy);
    parcel.WriteInt64(startTime);
    parcel.WriteInt64(endTime);
    parcel.WriteBool(hasTelephoneNumber);
    if (hasTelephoneNumber) {
        parcel.WriteString(telephoneNumber);
    }

    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    return 0;
}
} // namespace EDM
} // namespace OHOS
