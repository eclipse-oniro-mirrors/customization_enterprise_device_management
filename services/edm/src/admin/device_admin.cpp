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

#include "device_admin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"

namespace OHOS {
namespace EDM {
DeviceAdmin::DeviceAdmin(const AdminInfo& adminInfo): Admin(adminInfo)
{
    adminInfo_.adminType_ = AdminType::NORMAL;
}

bool DeviceAdmin::IsEnterpriseAdminKeepAlive() const
{
    return true;
}

bool DeviceAdmin::IsAllowedAcrossAccountSetPolicy() const
{
    return true;
}


bool DeviceAdmin::HasPermissionToCallServiceCode(uint32_t interfaceCode) const
{
    switch (interfaceCode) {
        case static_cast<uint32_t>(EdmInterfaceCode::REMOVE_DEVICE_ADMIN):
        case static_cast<uint32_t>(EdmInterfaceCode::SUBSCRIBE_MANAGED_EVENT):
        case static_cast<uint32_t>(EdmInterfaceCode::UNSUBSCRIBE_MANAGED_EVENT):
            return true;
        default:
            return false;
    }
}

bool DeviceAdmin::HasPermissionToHandlePolicy(const std::string &policyName, FuncOperateType operateType) const
{
#ifdef FEATURE_PC_ONLY
    return true;
#else
    if (policyName == PolicyName::POLICY_SET_BROWSER_POLICIES ||
        policyName == PolicyName::POLICY_MANAGED_BROWSER_POLICY) {
        return operateType == FuncOperateType::GET;
    }
    return false;
#endif
}

std::string DeviceAdmin::GetDisableSelfPermission() const
{
#ifdef FEATURE_PC_ONLY
    return EdmPermission::PERMISSION_ENTERPRISE_DEACTIVATE_DEVICE_ADMIN;
#else
    return EdmPermission::PERMISSION_DENIED;
#endif
}
} // namespace EDM
} // namespace OHOS