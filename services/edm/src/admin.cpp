/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "edm_log.h"
#include "ent_info.h"
#include "string_ex.h"

namespace OHOS {
namespace EDM {
Admin::Admin(const AdminInfo& other)
{
    adminInfo_.packageName_ = other.packageName_;
    adminInfo_.className_ = other.className_;
    adminInfo_.entInfo_ = other.entInfo_;
    adminInfo_.permission_ = other.permission_;
    adminInfo_.managedEvents_ = other.managedEvents_;
    adminInfo_.parentAdminName_ = other.parentAdminName_;
    adminInfo_.accessiblePolicies_ = other.accessiblePolicies_;
    adminInfo_.adminType_ = other.adminType_;
    adminInfo_.isDebug_ = other.isDebug_;
    adminInfo_.runningMode_ = other.runningMode_;
}

Admin& Admin::operator=(const AdminInfo& other)
{
    adminInfo_.packageName_ = other.packageName_;
    adminInfo_.className_ = other.className_;
    adminInfo_.entInfo_ = other.entInfo_;
    adminInfo_.permission_ = other.permission_;
    adminInfo_.managedEvents_ = other.managedEvents_;
    adminInfo_.parentAdminName_ = other.parentAdminName_;
    adminInfo_.accessiblePolicies_ = other.accessiblePolicies_;
    adminInfo_.adminType_ = other.adminType_;
    adminInfo_.isDebug_ = other.isDebug_;
    adminInfo_.runningMode_ = other.runningMode_;
    return *this;
}

Admin::Admin(const AppExecFwk::ExtensionAbilityInfo &abilityInfo, AdminType type, const EntInfo &entInfo,
    const std::vector<std::string> &permissions, bool isDebug)
{
    adminInfo_.adminType_ = type;
    adminInfo_.entInfo_ = entInfo;
    adminInfo_.permission_ = permissions;
    adminInfo_.packageName_ = abilityInfo.bundleName;
    adminInfo_.className_ = abilityInfo.name;
    adminInfo_.isDebug_ = isDebug;
}

Admin::Admin(const std::string &bundleName, AdminType type, const std::vector<std::string> &permissions)
{
    adminInfo_.packageName_ = bundleName;
    adminInfo_.adminType_ = type;
    adminInfo_.permission_ = permissions;
}

void Admin::SetParentAdminName(const std::string &parentAdminName)
{
    adminInfo_.parentAdminName_ = parentAdminName;
}

void Admin::SetAccessiblePolicies(const std::vector<std::string> &accessiblePolicies)
{
    adminInfo_.accessiblePolicies_ = accessiblePolicies;
}

bool Admin::CheckPermission(const std::string &permission)
{
    EDMLOGD("Admin::CheckPermission");
    return std::any_of(adminInfo_.permission_.begin(), adminInfo_.permission_.end(),
        [&permission](const std::string &item) { return item == permission; });
}

AdminType Admin::GetAdminType() const
{
    return adminInfo_.adminType_;
}
std::string Admin::GetParentAdminName() const
{
    return adminInfo_.parentAdminName_;
}
} // namespace EDM
} // namespace OHOS