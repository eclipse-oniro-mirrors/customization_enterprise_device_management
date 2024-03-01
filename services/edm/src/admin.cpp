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
bool Admin::CheckPermission(const std::string &permission)
{
    EDMLOGD("Admin::CheckPermission");
    return std::any_of(adminInfo_.permission_.begin(), adminInfo_.permission_.end(),
        [&permission](const std::string &item) { return item == permission; });
}

AdminType Admin::GetAdminType()
{
    return adminInfo_.adminType_;
}
std::string Admin::GetParentAdminName() const
{
    return adminInfo_.parentAdminName_;
}
} // namespace EDM
} // namespace OHOS