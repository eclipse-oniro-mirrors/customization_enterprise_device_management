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

#include "control_panel_plugin_fuzzer.h"

#include "common_fuzzer.h"
#include "control_panel_restricted_plugin.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 32;
constexpr int32_t FUZZ_USER_ID = 0;
constexpr int32_t MAX_TOGGLE_LIST_SIZE = 4;

void FuzzRestrictedPolicy(const uint8_t* data, size_t size, bool restricted)
{
    uint32_t code = POLICY_FUNC_CODE_NEW(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::CONTROL_PANEL_RESTRICTED);
    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(FUZZ_USER_ID);
    parcel.WriteBool(restricted);
    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);

    code = POLICY_FUNC_CODE_NEW(static_cast<uint32_t>(FuncOperateType::GET),
        EdmInterfaceCode::CONTROL_PANEL_RESTRICTED);
    MessageParcel getParcel;
    getParcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    getParcel.WriteInt32(FUZZ_USER_ID);
    getParcel.WriteInt32(static_cast<int32_t>(QueryPolicy::SELF));
    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, getParcel);

    ControlPanelRestrictedPlugin plugin;
    std::string policyData = restricted ? EdmConstants::CONST_TRUE : "";
    std::string mergeData = (CommonFuzzer::GetU32Data(data) % 2) ? EdmConstants::CONST_TRUE : "";
    plugin.OnAdminRemove("com.example.edmtest", policyData, mergeData, FUZZ_USER_ID);
}

void FuzzToggleListPolicy(const uint8_t* data, size_t size, uint32_t policyCode)
{
    int32_t pos = 0;
    int32_t stringSize = static_cast<int32_t>(size / 8);
    std::vector<std::string> toggleList;
    int32_t count = CommonFuzzer::GetU32Data(data) % MAX_TOGGLE_LIST_SIZE;
    for (int32_t i = 0; i < count; i++) {
        toggleList.emplace_back(CommonFuzzer::GetString(data, pos, stringSize, size));
    }

    uint32_t code = POLICY_FUNC_CODE_NEW(static_cast<uint32_t>(FuncOperateType::SET), policyCode);
    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(FUZZ_USER_ID);
    if (!parcel.WriteStringVector(toggleList)) {
        return;
    }
    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);

    code = POLICY_FUNC_CODE_NEW(static_cast<uint32_t>(FuncOperateType::GET), policyCode);
    MessageParcel getParcel;
    getParcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    getParcel.WriteInt32(FUZZ_USER_ID);
    getParcel.WriteInt32(static_cast<int32_t>(QueryPolicy::SELF));
    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, getParcel);
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_SIZE) {
        return 0;
    }

    bool restricted = CommonFuzzer::GetU32Data(data) % 2;
    FuzzRestrictedPolicy(data, size, restricted);
    FuzzToggleListPolicy(data, size, EdmInterfaceCode::CONTROL_PANEL_QUICK_TOGGLE_LIST);
    FuzzToggleListPolicy(data, size, EdmInterfaceCode::CONTROL_PANEL_TOP_TOGGLE_LIST);
    return 0;
}
} // namespace EDM
} // namespace OHOS