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

#include "virtual_device_admin.h"

#include "edm_ipc_interface_code.h"

namespace OHOS {
namespace EDM {
const std::string POLICY_ALLOW_ALL = "allow_all";

VirtualDeviceAdmin::VirtualDeviceAdmin(const AdminInfo& adminInfo): Admin(adminInfo)
{
    adminInfo_.adminType_ = AdminType::VIRTUAL_ADMIN;
}

bool VirtualDeviceAdmin::IsAllowedAcrossAccountSetPolicy() const
{
    return true;
}

bool VirtualDeviceAdmin::HasPermissionToHandlePolicy(const std::string &policyName, FuncOperateType operateType) const
{
    auto policies = adminInfo_.accessiblePolicies_;
    auto item = std::find_if(policies.begin(), policies.end(), [&](const std::string &policy) {
        return policy == POLICY_ALLOW_ALL || policy == policyName;
    });
    return item != policies.end();
}
} // namespace EDM
} // namespace OHOS