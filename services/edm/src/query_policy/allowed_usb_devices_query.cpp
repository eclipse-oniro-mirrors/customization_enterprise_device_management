/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "allowed_usb_devices_query.h"

#include "array_usb_device_id_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string AllowedUsbDevicesQuery::GetPolicyName()
{
    return "allowed_usb_devices";
}

std::string AllowedUsbDevicesQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return "ohos.permission.ENTERPRISE_MANAGE_USB";
}

ErrCode AllowedUsbDevicesQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("AllowedUsbDevicesQuery OnGetPolicy policyData : %{public}s, userId : %{public}d", policyData.c_str(),
        userId);
    std::vector<UsbDeviceId> usbDeviceIds;
    ArrayUsbDeviceIdSerializer::GetInstance()->Deserialize(policyData, usbDeviceIds);
    reply.WriteInt32(ERR_OK);
    reply.WriteUint32(usbDeviceIds.size());
    for (const auto &usbDeviceId : usbDeviceIds) {
        EDMLOGD("AllowedUsbDevicesQuery OnGetPolicy: currentData: vid: %{public}d, pid: %{public}d",
            usbDeviceId.GetVendorId(), usbDeviceId.GetProductId());
        if (!usbDeviceId.Marshalling(reply)) {
            EDMLOGE("AllowedUsbDevicesQuery OnGetPolicy: write parcel failed!");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS