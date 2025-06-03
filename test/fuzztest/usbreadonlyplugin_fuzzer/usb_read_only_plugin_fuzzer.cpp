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

#include "usb_read_only_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "ienterprise_device_mgr.h"
#include "func_code.h"
#include "message_parcel.h"
#define private public
#include "usb_read_only_plugin.h"
#undef private
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 16;
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
    int32_t stringSize = size / 6;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::USB_READ_ONLY;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(WITHOUT_USERID);
        if (operateType) {
            parcel.WriteParcelable(&admin);
            int32_t isReadOnly = CommonFuzzer::GetU32Data(data) % BINARY_DECISION_DIVISOR;
            parcel.WriteInt32(isReadOnly);
        } else {
            parcel.WriteString("");
            parcel.WriteInt32(0);
            parcel.WriteParcelable(&admin);
        }
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }
    UsbReadOnlyPlugin plugin;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType usbDeviceType;
    usbDeviceType.baseClass = CommonFuzzer::GetU32Data(data);
    usbDeviceType.subClass = CommonFuzzer::GetU32Data(data);
    usbDeviceType.protocol = CommonFuzzer::GetU32Data(data);
    usbDeviceType.isDeviceType = CommonFuzzer::GetU32Data(data) % 2;
    usbDeviceTypes.emplace_back(usbDeviceType);
    plugin.DealDisablePolicy(usbDeviceTypes);
    std::string fuzzString(reinterpret_cast<const char*>(data), size);
    std::string adminName = fuzzString;
    std::string policyData = fuzzString;
    std::string mergeData = fuzzString;
    int32_t userId = CommonFuzzer::GetU32Data(data);
    plugin.OnAdminRemove(adminName, policyData, mergeData, userId);
    return 0;
}
} // namespace EDM
} // namespace OHOS