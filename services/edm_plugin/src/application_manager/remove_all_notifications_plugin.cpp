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

#include "remove_all_notifications_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "notification_helper.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<RemoveAllNotificationsPlugin>());

RemoveAllNotificationsPlugin::RemoveAllNotificationsPlugin()
{
    policyCode_ = EdmInterfaceCode::REMOVE_ALL_NOTIFICATIONS;
    policyName_ = PolicyName::POLICY_REMOVE_ALL_NOTIFICATIONS;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NOTIFICATION,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode RemoveAllNotificationsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    int32_t accountId = data.ReadInt32();
    if (accountId < 0) {
        EDMLOGE("RemoveAllNotificationsPlugin: accountId is invalid, %{public}d", accountId);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    EDMLOGI("RemoveAllNotificationsPlugin OnHandlePolicy, accountId=%{public}d", accountId);
    int32_t ret = RemoveAllNotifications(accountId);
    if (ret != ERR_OK) {
        EDMLOGE("RemoveAllNotificationsPlugin: RemoveAllNotifications failed, %{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}

int32_t RemoveAllNotificationsPlugin::RemoveAllNotifications(int32_t accountId)
{
    return OHOS::Notification::NotificationHelper::RemoveAllNotificationsAsAdmin(accountId);
}
} // namespace EDM
} // namespace OHOS
