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

#include "set_watermark_image_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "utils.h"
#define private public
#include "set_watermark_image_plugin.h"
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 48;
constexpr size_t WITHOUT_USERID = 0;

void SetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size,
    AppExecFwk::ElementName admin, bool isSet)
{
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    int32_t pos = 0;
    int32_t stringSize = size / 8;
    
    if (isSet) {
        parcel.WriteString(EdmConstants::SecurityManager::SET_SINGLE_WATERMARK_TYPE);
        std::string bundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
        int32_t accountId = CommonFuzzer::GetU32Data(data, pos, size);
        int32_t imageSize = CommonFuzzer::GetU32Data(data, pos, size);
        int32_t width = CommonFuzzer::GetU32Data(data, pos, size) % 2000;
        int32_t height = CommonFuzzer::GetU32Data(data, pos, size) % 2000;
        
        parcel.WriteString(bundleName);
        parcel.WriteInt32(accountId);
        parcel.WriteInt32(width);
        parcel.WriteInt32(height);
        parcel.WriteInt32(imageSize);
        
        if (imageSize > 0 && pos + imageSize <= size) {
            parcel.WriteRawData(data + pos, imageSize);
        }
    } else {
        std::string bundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
        int32_t accountId = CommonFuzzer::GetU32Data(data, pos, size);
        parcel.WriteString(bundleName);
        parcel.WriteInt32(accountId);
    }
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
    int32_t stringSize = size / 8;
    
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::SET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::WATERMARK_IMAGE;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        SetParcelContent(parcel, data, size, admin, operateType == static_cast<uint32_t>(FuncOperateType::SET));

        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }

    SetWatermarkImagePlugin plugin;
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string policyData = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string mergeData = CommonFuzzer::GetString(data, pos, stringSize, size);
    int32_t userId = CommonFuzzer::GetU32Data(data, pos, size);
    
    plugin.OnAdminRemove(adminName, policyData, mergeData, userId);
    
    int32_t systemAbilityId = CommonFuzzer::GetU32Data(data, pos, size) % 1000;
    plugin.OnOtherServiceStart(systemAbilityId);
    
    std::string othersMergePolicyData;
    plugin.GetOthersMergePolicyData(adminName, userId, othersMergePolicyData);

    return 0;
}
} // namespace EDM
} // namespace OHOS
