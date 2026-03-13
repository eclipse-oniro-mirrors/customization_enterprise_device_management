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

#include "disallowed_usb_devices_plugin_fuzzer.h"

#include <system_ability_definition.h>

#include "array_usb_device_type_serializer.h"
#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "usb_interface_type.h"
#include "utils.h"
#define private public
#include "disallowed_usb_devices_plugin.h"
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 32;
constexpr size_t WITHOUT_USERID = 0;

void SetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size, AppExecFwk::ElementName admin)
{
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    int32_t pos = 0;
    int32_t stringSize = size / 8;
    int32_t numDevices = CommonFuzzer::GetU32Data(data, pos, size) % 250 + 1;
    std::vector<USB::UsbDeviceType> usbDevices;
    for (int32_t i = 0; i < numDevices && pos + stringSize < size; i++) {
        USB::UsbDeviceType device;
        device.baseClass = CommonFuzzer::GetU32Data(data, pos, size);
        device.subClass = CommonFuzzer::GetU32Data(data, pos, size);
        device.protocol = CommonFuzzer::GetU32Data(data, pos, size);
        device.isDeviceType = CommonFuzzer::GetU32Data(data, pos, size);
        usbDevices.push_back(device);
    }
    parcel.WriteUint32(usbDevices.size());
    for (const auto &device : usbDevices) {
        if (!device.Marshalling(parcel)) {
            break;
        }
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
        uint32_t code = EdmInterfaceCode::DISALLOWED_USB_DEVICES;
        code = POLICY_FUNC_CODE(operateType, code);

        AppExecFwk::ElementName admin;
        admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
        admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
        MessageParcel parcel;
        SetParcelContent(parcel, data, size, admin);

        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    }

    DisallowedUsbDevicesPlugin plugin;
    std::vector<USB::UsbDeviceType> mData;
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;
    int32_t numDevices = CommonFuzzer::GetU32Data(data, pos, size) % 250 + 1;
    for (int32_t i = 0; i < numDevices && pos + stringSize < size; i++) {
        USB::UsbDeviceType device;
        device.baseClass = CommonFuzzer::GetU32Data(data, pos, size);
        device.subClass = CommonFuzzer::GetU32Data(data, pos, size);
        device.protocol = CommonFuzzer::GetU32Data(data, pos, size);
        device.isDeviceType = CommonFuzzer::GetU32Data(data, pos, size);
        mData.push_back(device);
    }
    
    plugin.OnSetPolicy(mData, currentData, mergeData, WITHOUT_USERID);
    plugin.OnRemovePolicy(mData, currentData, mergeData, WITHOUT_USERID);
    
    std::string policyData;
    ArrayUsbDeviceTypeSerializer::GetInstance()->Serialize(mData, policyData);
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    plugin.OnGetPolicy(policyData, dataParcel, replyParcel, WITHOUT_USERID);

    return 0;
}
} // namespace EDM
} // namespace OHOS
