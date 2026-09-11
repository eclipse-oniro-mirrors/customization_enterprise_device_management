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

#include "publish_form_to_desktop_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "handle_policy_data.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "publish_form_to_desktop_param.h"
#include "utils.h"
#define private public
#include "publish_form_to_desktop_plugin.h"
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 24;
constexpr size_t STRING_COUNT = 8;
constexpr size_t INT32_COUNT = 4;

PublishFormToDesktopParam GenerateParam(const uint8_t* data, size_t size, int32_t& pos, int32_t stringSize)
{
    PublishFormToDesktopParam param;
    param.bundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
    param.moduleName = CommonFuzzer::GetString(data, pos, stringSize, size);
    param.abilityName = CommonFuzzer::GetString(data, pos, stringSize, size);
    param.name = CommonFuzzer::GetString(data, pos, stringSize, size);
    param.dimension = CommonFuzzer::GetU32Data(data, pos, size);
    return param;
}

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

    uint32_t code = POLICY_FUNC_CODE_NEW(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param = GenerateParam(data, size, pos, stringSize);
    int32_t userId = CommonFuzzer::GetU32Data(data, pos, size);

    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(userId);
    param.Marshalling(parcel);
    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);

    PublishFormToDesktopPlugin plugin;
    MessageParcel requestData;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    PublishFormToDesktopParam paramDirect = GenerateParam(data, size, pos, stringSize);
    int32_t userIdDirect = CommonFuzzer::GetU32Data(data, pos, size);
    paramDirect.Marshalling(requestData);
    plugin.OnHandlePolicy(code, requestData, reply, handlePolicyData, userIdDirect);
    return 0;
}
} // namespace EDM
} // namespace OHOS
