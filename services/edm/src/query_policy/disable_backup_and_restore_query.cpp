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

#include "disable_backup_and_restore_query.h"
#include "edm_constants.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
std::string DisableBackupAndRestoreQuery::GetPolicyName()
{
    return PolicyName::POLICY_DISABLE_BACKUP_AND_RESTORE;
}

std::string DisableBackupAndRestoreQuery::GetPermission(IPlugin::PermissionType permissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
}

ErrCode DisableBackupAndRestoreQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return GetBoolPolicy(policyData, reply);
}
} // namespace EDM
} // namespace OHOS