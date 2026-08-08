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

#include "apn_utils_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "apn_utils.h"
#undef protected
#undef private
#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 24;

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
    int32_t stringSize = size / 8;

    std::string apnId = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string key1 = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string val1 = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string key2 = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string val2 = CommonFuzzer::GetString(data, pos, stringSize, size);

    std::map<std::string, std::string> apnInfo;
    apnInfo[key1] = val1;
    apnInfo[key2] = val2;

    ApnUtilsPassword apnUtilsPassword;

    ApnUtils::ApnInsert(apnInfo, apnUtilsPassword);
    ApnUtils::ApnDelete(apnId);
    ApnUtils::ApnUpdate(apnInfo, apnId, apnUtilsPassword);
    ApnUtils::ApnQuery(apnInfo);
    ApnUtils::ApnQuery(apnId);
    ApnUtils::ApnSetPrefer(apnId);
    return 0;
}
} // namespace EDM
} // namespace OHOS
