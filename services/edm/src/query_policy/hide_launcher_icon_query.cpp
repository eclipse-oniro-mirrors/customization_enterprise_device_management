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

#include "hide_launcher_icon_query.h"

#include "edm_data_ability_utils.h"
#include "edm_constants.h"
#include "edm_os_account_manager_impl.h"
#include "os_account_manager.h"
#include "parameters.h"

#include <string>
#include <vector>
#include <sstream>

namespace OHOS {
namespace EDM {
std::string HideLauncherIconQuery::GetPolicyName()
{
    return PolicyName::POLICY_HIDE_LAUNCHER_ICON;
}

std::string HideLauncherIconQuery::GetPermission(IPlugin::PermissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
}

ErrCode HideLauncherIconQuery::QueryPolicy(std::string &policyData,
    MessageParcel &data, MessageParcel &reply, int32_t userId, bool isAdminNull)
{
    int32_t currentUserId = std::make_shared<EdmOsAccountManagerImpl>()->GetCurrentUserId();
    if (currentUserId < 0) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (userId != currentUserId) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    if (isAdminNull) {
        std::string result;
        std::string uri = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_"
            + std::to_string(userId) + "?Proxy=true";
        ErrCode code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(uri,
            EdmConstants::ApplicationManager::ENTERPRISE_CUSTOM_HIDE_APP_LIST, result);
        if (code != ERR_OK) {
            EDMLOGE("HideLauncherIconQuery::get data from database failed : %{public}d.", code);
            reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        std::vector<std::string> packages;
        std::istringstream iss(result);
        std::string package;
        while (std::getline(iss, package, ',')) {
            packages.push_back(package);
        }

        reply.WriteInt32(ERR_OK);
        reply.WriteStringVector(packages);
        return ERR_OK;
    }
    return GetArrayStringPolicy(policyData, reply);
}
} // namespace EDM
} // namespace OHOS