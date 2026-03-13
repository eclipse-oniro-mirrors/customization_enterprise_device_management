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

#include "disallowed_bluetooth_protocols_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "array_int_serializer.h"
#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "utils.h"
#define private public
#include "disallowed_bluetooth_protocols_plugin.h"
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 24;
constexpr size_t WITHOUT_USERID = 0;

void SetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size, AppExecFwk::ElementName admin)
{
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    int32_t pos = 0;
    int32_t numProtocols = CommonFuzzer::GetU32Data(data, pos, size) % 12000 + 1;
    std::vector<int32_t> protocols;
    for (int32_t i = 0; i < numProtocols && pos + sizeof(int32_t) < size; i++) {
        protocols.push_back(CommonFuzzer::GetU32Data(data, pos, size));
    }
    parcel.WriteInt32Vector(protocols);
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
    int32_t stringSize = size / 4;
    
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::SET);
        operateType <= static_cast<uint32_t>(FuncOperateType::GET); operateType++) {
        uint32_t code = EdmInterfaceCode::DISALLOWED_BLUETOOTH_PROTOCOLS;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        SetParcelContent(parcel, data, size, admin);

        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }

    DisallowedBluetoothProtocolsPlugin plugin;
    std::vector<int32_t> mData;
    std::vector<int32_t> currentData;
    std::vector<int32_t> mergeData;
    int32_t numProtocols = CommonFuzzer::GetU32Data(data, pos, size) % 12000 + 1;
    for (int32_t i = 0; i < numProtocols && pos + sizeof(int32_t) < size; i++) {
        mData.push_back(CommonFuzzer::GetU32Data(data, pos, size));
    }
    
    plugin.OnSetPolicy(mData, currentData, mergeData, WITHOUT_USERID);
    plugin.OnRemovePolicy(mData, currentData, mergeData, WITHOUT_USERID);
    
    std::string policyData;
    ArrayIntSerializer::GetInstance()->Serialize(mData, policyData);
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    plugin.OnGetPolicy(policyData, dataParcel, replyParcel, WITHOUT_USERID);
    
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    plugin.OnAdminRemove(adminName, currentData, mergeData, WITHOUT_USERID);
    
    bool isGlobalChanged = CommonFuzzer::GetU32Data(data, pos, size) % 2;
    plugin.OnChangedPolicyDone(isGlobalChanged);

    return 0;
}
} // namespace EDM
} // namespace OHOS
