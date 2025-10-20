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

#include "byod_admin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"

namespace OHOS {
namespace EDM {
const char* const POLICY_DISABLE_RESET_FACTORY = "disable_reset_factory";
const char* const POLICY_DISABLE_NEAR_LINK = "policy_near_link";
const char* const POLICY_DISABLE_SCREEN_RECORD = "policy_screen_record";
const char* const POLICY_DISABLE_SCREEN_SHOT = "policy_screen_shot";
ByodAdmin::ByodAdmin(const AdminInfo& adminInfo): Admin(adminInfo)
{
    adminInfo_.adminType_ = AdminType::BYOD;
    adminInfo_.accessiblePolicies_ = {
        PolicyName::POLICY_DISABLED_BLUETOOTH, PolicyName::POLICY_DISABLE_CAMERA, PolicyName::POLICY_DISABLED_HDC,
        PolicyName::POLICY_DISABLE_MICROPHONE, PolicyName::POLICY_DISABLE_USB, PolicyName::POLICY_DISALLOWED_TETHERING,
        PolicyName::POLICY_DISABLE_WIFI, POLICY_DISABLE_RESET_FACTORY, POLICY_DISABLE_NEAR_LINK,
        POLICY_DISABLE_SCREEN_RECORD, POLICY_DISABLE_SCREEN_SHOT
    };
}

bool ByodAdmin::IsDisallowedUninstall() const
{
    return true;
}

bool ByodAdmin::HasPermissionToCallServiceCode(uint32_t interfaceCode) const
{
    switch (interfaceCode) {
        case static_cast<uint32_t>(EdmInterfaceCode::REMOVE_DEVICE_ADMIN):
        case static_cast<uint32_t>(EdmInterfaceCode::IS_BYOD_ADMIN):
            return true;
        default:
            return false;
    }
}

bool ByodAdmin::HasPermissionToHandlePolicy(const std::string &policyName, FuncOperateType operateType) const
{
    const auto &policies = adminInfo_.accessiblePolicies_;
    return std::find(policies.begin(), policies.end(), policyName) != policies.end();
}

std::string ByodAdmin::GetDisableSelfPermission() const
{
    return EdmPermission::PERMISSION_GET_ADMINPROVISION_INFO;
}
} // namespace EDM
} // namespace OHOS