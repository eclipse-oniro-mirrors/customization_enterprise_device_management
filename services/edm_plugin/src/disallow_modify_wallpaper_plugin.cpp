/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "disallow_modify_wallpaper_plugin.h"

#include <ipc_skeleton.h>
#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "os_account_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableModifyWallpaperPlugin::GetPlugin());
const std::string CONSTRAINT_WALLPAPER = "constraint.wallpaper.set";

void DisableModifyWallpaperPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisableModifyWallpaperPlugin, bool>> ptr)
{
    EDMLOGD("DisableModifyWallpaperPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_MODIFY_WALLPAPER, PolicyName::POLICY_DISALLOW_MODIFY_WALLPAPER,
        EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableModifyWallpaperPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableModifyWallpaperPlugin::OnAdminRemove);
}

ErrCode DisableModifyWallpaperPlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergeData,
    int32_t userId)
{
    EDMLOGD("DisableModifyWallpaperPlugin::OnSetPolicy, data: %{public}d, currentData: %{public}d, "
            "mergeData: %{public}d", data, currentData, mergeData);
    if (mergeData) {
        currentData = data;
        return ERR_OK;
    }
    ErrCode ret = SetModifyWallpaperPolicy(data, userId);
    EDMLOGD("DisableModifyWallpaperPlugin::SetSudoPolicy ret: %{public}d", ret);
    if (FAILED(ret)) {
        EDMLOGE("SetModifyWallpaperPolicy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

ErrCode DisableModifyWallpaperPlugin::OnAdminRemove(const std::string &adminName, bool &data, bool &mergeData,
    int32_t userId)
{
    EDMLOGD("DisableModifyWallpaperPlugin::OnAdminRemove, adminName: %{public}s, data: %{public}d, "
            "mergeData: %{public}d", adminName.c_str(), data, mergeData);
    // admin 移除时，综合策略为非禁用，且移除的策略为禁用，则更新策略为非禁用
    if (!mergeData && data) {
        ErrCode ret = SetModifyWallpaperPolicy(false, userId);
        if (FAILED(ret)) {
            EDMLOGE("SetModifyWallpaperPolicy failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode DisableModifyWallpaperPlugin::SetModifyWallpaperPolicy(bool policy, int32_t userId)
{
    EDMLOGI("SetModifyWallpaperPolicy, policy: %{public}d", policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_WALLPAPER);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, policy, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("SetModifyWallpaperPolicy, SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}
} // namespace EDM
} // namespace OHOS