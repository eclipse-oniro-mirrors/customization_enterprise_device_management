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

#include <algorithm>

#include "array_odd_burn_usb_device_serializer.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "policy_manager.h"

namespace OHOS {
namespace EDM {
std::string IsAllowedOddBurnQuery::GetPolicyName()
{
    // Keep device-level policy name for historical IsAllowedOddBurn behavior:
    // IPolicyQuery loads policyData via GetPolicyName().
    return PolicyName::POLICY_ALLOWED_ODD_BURN_USB_DEVICES;
}

std::string IsAllowedOddBurnQuery::GetPermission(IPlugin::PermissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB;
}

bool IsAllowedOddBurnQuery::MatchOddBurnDevice(const std::vector<OddBurnUsbDevice> &devices, int32_t vendorId,
    int32_t productId, const std::string &serial) const
{
    auto allowedDevice = std::find_if(devices.begin(), devices.end(),
        [vendorId, productId, serial](const OddBurnUsbDevice &device) {
            if (device.GetSerial().empty()) {
                return device.GetVendorId() == vendorId && device.GetProductId() == productId;
            }
            return device.GetVendorId() == vendorId && device.GetProductId() == productId &&
                device.GetSerial() == serial;
        });
    return allowedDevice != devices.end();
}

bool IsAllowedOddBurnQuery::ParseOddBurnPolicy(const std::string &policyData,
    std::vector<OddBurnUsbDevice> &devices) const
{
    if (policyData.empty()) {
        devices.clear();
        return true;
    }
    return ArrayOddBurnUsbDeviceSerializer::GetInstance()->Deserialize(policyData, devices);
}

void IsAllowedOddBurnQuery::WriteAllowedResult(MessageParcel &reply, bool isAllowed) const
{
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isAllowed);
}

ErrCode IsAllowedOddBurnQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    int32_t vendorId = data.ReadInt32();
    int32_t productId = data.ReadInt32();
    std::string serial = data.ReadString();
    EDMLOGI("IsAllowedOddBurnQuery::QueryPolicy userId=%{public}d vendorId=%{public}d, productId=%{public}d",
        userId, vendorId, productId);

    // 1. Account-level first (short-circuit). policyData from GetPolicyName() is device-level.
    std::string accountPolicyData;
    PolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_ALLOWED_ODD_BURN_USB_DEVICES_FOR_ACCOUNT,
        accountPolicyData, userId);
    std::vector<OddBurnUsbDevice> accountDevices;
    if (!ParseOddBurnPolicy(accountPolicyData, accountDevices)) {
        EDMLOGE("IsAllowedOddBurnQuery::QueryPolicy account Deserialize failed");
        reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    bool accountHasPolicy = !accountDevices.empty();
    if (accountHasPolicy && MatchOddBurnDevice(accountDevices, vendorId, productId, serial)) {
        EDMLOGI("IsAllowedOddBurnQuery::QueryPolicy account match, allow");
        WriteAllowedResult(reply, true);
        return ERR_OK;
    }

    // 2. Account not matched → match device-level policy already loaded into policyData.
    std::vector<OddBurnUsbDevice> deviceDevices;
    if (!ParseOddBurnPolicy(policyData, deviceDevices)) {
        EDMLOGE("IsAllowedOddBurnQuery::QueryPolicy device Deserialize failed");
        reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    bool deviceHasPolicy = !deviceDevices.empty();
    if (deviceHasPolicy && MatchOddBurnDevice(deviceDevices, vendorId, productId, serial)) {
        EDMLOGI("IsAllowedOddBurnQuery::QueryPolicy device match, allow");
        WriteAllowedResult(reply, true);
        return ERR_OK;
    }

    // Neither matched: allow only when no policy at either level.
    bool isAllowed = !accountHasPolicy && !deviceHasPolicy;
    EDMLOGI("IsAllowedOddBurnQuery::QueryPolicy isAllowed=%{public}d accountHas=%{public}d deviceHas=%{public}d",
        isAllowed, accountHasPolicy, deviceHasPolicy);
    WriteAllowedResult(reply, isAllowed);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
