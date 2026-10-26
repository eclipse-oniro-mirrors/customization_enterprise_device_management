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

#include "is_allowed_odd_burn_query.h"

#include "array_odd_burn_usb_device_serializer.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "odd_burn_usb_device.h"

namespace OHOS {
namespace EDM {
std::string IsAllowedOddBurnQuery::GetPolicyName()
{
    return PolicyName::POLICY_ALLOWED_ODD_BURN_USB_DEVICES;
}

std::string IsAllowedOddBurnQuery::GetPermission(IPlugin::PermissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB;
}

ErrCode IsAllowedOddBurnQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    int32_t vendorId = data.ReadInt32();
    int32_t productId = data.ReadInt32();
    std::string serial = data.ReadString();
    EDMLOGI("IsAllowedOddBurnQuery::QueryPolicy vendorId=%{public}d, productId=%{public}d, serial=%{public}s",
        vendorId, productId, serial.c_str());
    std::vector<OddBurnUsbDevice> usbDevices;
    if (!ArrayOddBurnUsbDeviceSerializer::GetInstance()->Deserialize(policyData, usbDevices)) {
        EDMLOGE("IsAllowedOddBurnQuery::QueryPolicy Deserialize failed");
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool isAllowed = true;
    if (!usbDevices.empty()) {
        auto allowedDevice = std::find_if(usbDevices.begin(), usbDevices.end(), [=](auto &device) {
            if (device.GetSerial().empty()) {
                return device.GetVendorId() == vendorId && device.GetProductId() == productId;
            }
            return device.GetVendorId() == vendorId && device.GetProductId() == productId &&
                device.GetSerial() == serial;
        });
        isAllowed = (allowedDevice != usbDevices.end());
    }
    EDMLOGI("IsAllowedOddBurnQuery::QueryPolicy isAllowed=%{public}d", isAllowed);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isAllowed);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
