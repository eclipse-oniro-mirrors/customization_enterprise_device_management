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

#include "policy_query_config.h"

#include "edm_constants.h"

namespace OHOS {
namespace EDM {

std::string PermissionConfig::GetPermission(IPlugin::PermissionType type,
    const std::string &permissionTag) const
{
    switch (pattern) {
        case PermissionPattern::RESTRICTION:
            if (hasByod && type == IPlugin::PermissionType::BYOD_DEVICE_ADMIN) {
                return EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS;
            }
            return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
        case PermissionPattern::SPECIFIC:
            return specificPermission ? std::string(specificPermission) : "";
        case PermissionPattern::TAG:
            if (!permissionTag.empty() && type == IPlugin::PermissionType::SUPER_DEVICE_ADMIN) {
                return tagPermission ? std::string(tagPermission) : "";
            }
            if (type == IPlugin::PermissionType::BYOD_DEVICE_ADMIN) {
                return byodPermission ? std::string(byodPermission) :
                    (specificPermission ? std::string(specificPermission) : "");
            }
            return specificPermission ? std::string(specificPermission) : "";
        default:
            return "";
    }
}

PermissionConfig PermissionConfig::RestrictionPermission(bool hasByod)
{
    return {PermissionPattern::RESTRICTION, hasByod, nullptr, nullptr, nullptr};
}

PermissionConfig PermissionConfig::RestrictionPermission()
{
    return {PermissionPattern::RESTRICTION, false, nullptr, nullptr, nullptr};
}

PermissionConfig PermissionConfig::SpecificPermission(const char* permission)
{
    return {PermissionPattern::SPECIFIC, false, permission, nullptr, nullptr};
}

PermissionConfig PermissionConfig::TagPermission(const char* tagPerm,
    const char* defaultPerm, const char* byodPerm)
{
    return {PermissionPattern::TAG, false, defaultPerm, tagPerm, byodPerm};
}

} // namespace EDM
} // namespace OHOS
