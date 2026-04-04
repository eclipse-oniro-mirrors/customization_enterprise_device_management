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

#include "disable_screen_lock_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "screenlock_manager.h"
#include "edm_os_account_manager_impl.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(DisableScreenLockPlugin::GetPlugin());

void DisableScreenLockPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisableScreenLockPlugin, bool>> ptr)
{
    EDMLOGI("DisableScreenLockPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    IPlugin::PolicyPermissionConfig config =
        IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_SCREEN_LOCK,
        PolicyName::POLICY_DISABLE_SCREEN_LOCK, config, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableScreenLockPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisableScreenLockPlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergeData,
    int32_t userId)
{
    EDMLOGD("DisableScreenLockPlugin::OnSetPolicy, data: %{public}d.", data);
    int32_t curUserId = GetCurrentUserId();
    if (curUserId == -1) {
        EDMLOGE("DisableScreenLockPlugin user id error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = ScreenLock::ScreenLockManager::GetInstance()->SetScreenLockDisabled(data, curUserId);
    if (data && ret == ScreenLock::SCREEN_FAIL) {
        EDMLOGE("DisableScreenLockPlugin device has already set screen lock");
        return EdmReturnErrCode::SCREEN_LOCK_PWD_HAS_BEEN_SET;
    }
    if (ret != ScreenLock::E_SCREENLOCK_OK) {
        EDMLOGE("SetScreenLockDisabled failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

int32_t DisableScreenLockPlugin::GetCurrentUserId()
{
    std::vector<int32_t> ids;
    ErrCode ret = std::make_shared<EdmOsAccountManagerImpl>()->QueryActiveOsAccountIds(ids);
    if (FAILED(ret) || ids.empty()) {
        EDMLOGE("DisableScreenLockPlugin GetCurrentUserId failed");
        return -1;
    }
    EDMLOGD("DisableScreenLockPlugin GetCurrentUserId");
    return (ids.at(0));
}

ErrCode DisableScreenLockPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    int32_t curUserId = GetCurrentUserId();
    if (curUserId == -1) {
        EDMLOGE("DisableScreenLockPlugin user id error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool isDisabled = false;
    int32_t ret = ScreenLock::ScreenLockManager::GetInstance()->IsScreenLockDisabled(curUserId, isDisabled);
    if (ret != ScreenLock::E_SCREENLOCK_OK) {
        EDMLOGE("DisableScreenLockPlugin:OnGetPolicy fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisabled);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
