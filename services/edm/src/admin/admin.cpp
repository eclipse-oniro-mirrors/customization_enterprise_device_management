/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "admin.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "ent_info.h"
#include "string_ex.h"

namespace OHOS {
namespace EDM {
Admin::Admin(const AdminInfo& adminInfo)
{
    adminInfo_ = adminInfo;
}

AdminType Admin::GetAdminType() const
{
    return adminInfo_.adminType_;
}

std::string Admin::GetParentAdminName() const
{
    return adminInfo_.parentAdminName_;
}

bool Admin::IsSuperAdmin() const
{
    return adminInfo_.adminType_ == AdminType::ENT;
}

bool Admin::IsDisallowedUninstall() const
{
    return false;
}

bool Admin::IsEnterpriseAdminKeepAlive() const
{
    return false;
}

bool Admin::IsAllowedAcrossAccountSetPolicy() const
{
    return false;
}

bool Admin::HasPermissionToCallServiceCode(uint32_t interfaceCode) const
{
    return false;
}

bool Admin::HasPermissionToHandlePolicy(const std::string &policyName, FuncOperateType operateType) const
{
    return false;
}

std::string Admin::GetDisableSelfPermission() const
{
    return EdmPermission::PERMISSION_DENIED;
}
} // namespace EDM
} // namespace OHOS