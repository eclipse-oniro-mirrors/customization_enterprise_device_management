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

#include "allowed_usb_devices_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "allowed_usb_devices_plugin.h"
#include "array_usb_device_id_serializer.h"
#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "get_data_template.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "plugin_manager.h"
#include "usb_device_id.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 20;
constexpr int32_t WITHOUT_USERID = 0;
constexpr int32_t USB_DEVICE_ID_SIZE = 1;

void DoSomethingInterestingWithAPI(const uint8_t* data, size_t size, int32_t pos, int32_t stringSize)
{
    AllowUsbDevicesPlugin plugin;
    std::string adminName = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::vector<UsbDeviceId> emptyData;
    std::vector<UsbDeviceId> policyData = { GetData<UsbDeviceId>() };
    std::vector<UsbDeviceId> mergeData = { GetData<UsbDeviceId>() };
    int32_t userId = CommonFuzzer::GetU32Data(data);
    plugin.OnAdminRemove(adminName, emptyData, mergeData, userId);
    plugin.OnAdminRemove(adminName, policyData, emptyData, userId);
    plugin.OnAdminRemove(adminName, policyData, mergeData, userId);

    int32_t systemAbilityId = CommonFuzzer::GetU32Data(data);
    plugin.OnOtherServiceStart(systemAbilityId);
}

extern "C" int LLVMFuzzerInitialize(const uint8_t* data, size_t size)
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
    int32_t pos = 0;
    int32_t stringSize = size / 10;
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
        operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        uint32_t code = EdmInterfaceCode::ALLOWED_USB_DEVICES;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
        parcel.WriteInt32(WITHOUT_USERID);
        if (operateType) {
            parcel.WriteParcelable(&admin);
            parcel.WriteInt32(USB_DEVICE_ID_SIZE);
            UsbDeviceId usbDeviceId = GetData<UsbDeviceId>();
            std::vector<UsbDeviceId> usbDeviceIds = { usbDeviceId };
            std::for_each(usbDeviceIds.begin(), usbDeviceIds.end(),
                [&](const auto usbDeviceId) { usbDeviceId.Marshalling(parcel); });
        } else {
            parcel.WriteString("");
            parcel.WriteInt32(0);
            parcel.WriteParcelable(&admin);
        }
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }

    DoSomethingInterestingWithAPI(data, size, pos, stringSize);
    return 0;
}
} // namespace EDM
} // namespace OHOS