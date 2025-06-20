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

#include "disallowed_nearlink_protocols_plugin_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "disallowed_nearlink_protocols_plugin.h"
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
constexpr size_t MIN_SIZE = 10;

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
    int32_t stringSize = size / 6;
    DisallowedNearlinkProtocolsPlugin plugin;
    std::string policyData = CommonFuzzer::GetString(data, pos, stringSize, size);
    MessageParcel requestData;
    requestData.WriteString(CommonFuzzer::GetString(data, pos, stringSize, size));
    MessageParcel reply;
    reply.WriteString("");
    int32_t intData = CommonFuzzer::GetU32Data(data);
    std::vector<int32_t> intDataVector = {intData};
    std::vector<int32_t> currentData = {intData};
    std::vector<int32_t> mergeData = {intData};
    int32_t userId = CommonFuzzer::GetU32Data(data);
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);

    plugin.OnGetPolicy(policyData, requestData, reply, userId);
    plugin.OnSetPolicy(intDataVector, currentData, mergeData, userId);
    plugin.OnGetPolicy(policyData, requestData, reply, userId);
    plugin.OnAdminRemove(adminName, intDataVector, mergeData, userId);
    return 0;
}
} // namespace EDM
} // namespace OHOS