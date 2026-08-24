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

#include "allowed_odd_burn_usb_devices_query.h"

#include "array_odd_burn_usb_device_serializer.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "odd_burn_usb_device.h"

namespace OHOS {
namespace EDM {
std::string AllowedOddBurnUsbDevicesQuery::GetPolicyName()
{
    return PolicyName::POLICY_ALLOWED_ODD_BURN_USB_DEVICES;
}

std::string AllowedOddBurnUsbDevicesQuery::GetPermission(IPlugin::PermissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB;
}

ErrCode AllowedOddBurnUsbDevicesQuery::QueryPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("AllowedOddBurnUsbDevicesQuery QueryPolicy");
    std::vector<OddBurnUsbDevice> usbDevices;
    if (!ArrayOddBurnUsbDeviceSerializer::GetInstance()->Deserialize(policyData, usbDevices)) {
        EDMLOGE("AllowedOddBurnUsbDevicesQuery Deserialize error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    if (!ArrayOddBurnUsbDeviceSerializer::GetInstance()->WriteRawDataToParcel(reply, usbDevices)) {
        EDMLOGE("AllowedOddBurnUsbDevicesQuery WriteRawDataToParcel failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("AllowedOddBurnUsbDevicesQuery QueryPolicy return %{public}zu devices", usbDevices.size());
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
