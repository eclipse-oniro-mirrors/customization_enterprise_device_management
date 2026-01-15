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

#include "super_device_admin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"

namespace OHOS {
namespace EDM {
SuperDeviceAdmin::SuperDeviceAdmin(const AdminInfo& adminInfo): Admin(adminInfo)
{
    adminInfo_.adminType_ = AdminType::ENT;
}

bool SuperDeviceAdmin::IsDisallowedUninstall() const
{
    return true;
}

bool SuperDeviceAdmin::IsEnterpriseAdminKeepAlive() const
{
    return true;
}

bool SuperDeviceAdmin::IsAllowedAcrossAccountSetPolicy() const
{
    return true;
}


bool SuperDeviceAdmin::HasPermissionToCallServiceCode(uint32_t interfaceCode) const
{
    switch (interfaceCode) {
        case static_cast<uint32_t>(EdmInterfaceCode::REMOVE_DEVICE_ADMIN):
        case static_cast<uint32_t>(EdmInterfaceCode::SUBSCRIBE_MANAGED_EVENT):
        case static_cast<uint32_t>(EdmInterfaceCode::UNSUBSCRIBE_MANAGED_EVENT):
        case static_cast<uint32_t>(EdmInterfaceCode::AUTHORIZE_ADMIN):
        case static_cast<uint32_t>(EdmInterfaceCode::SET_DELEGATED_POLICIES):
        case static_cast<uint32_t>(EdmInterfaceCode::GET_DELEGATED_POLICIES):
        case static_cast<uint32_t>(EdmInterfaceCode::GET_DELEGATED_BUNDLE_NAMES):
#if defined(FEATURE_PC_ONLY)
        case static_cast<uint32_t>(EdmInterfaceCode::ENABLE_DEVICE_ADMIN):
        case static_cast<uint32_t>(EdmInterfaceCode::DISABLE_DEVICE_ADMIN):
#endif
            return true;
        default:
            return false;
    }
}

bool SuperDeviceAdmin::HasPermissionToHandlePolicy(const std::string &policyName, FuncOperateType operateType) const
{
    return true;
}

std::string SuperDeviceAdmin::GetDisableSelfPermission() const
{
    return EdmPermission::PERMISSION_ENTERPRISE_DEACTIVATE_DEVICE_ADMIN;
}
} // namespace EDM
} // namespace OHOS