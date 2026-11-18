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

#include "remove_notification_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "errors.h"
#include "iplugin_manager.h"
#include "notification_helper.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr int32_t ANS_COMMON_ERR_OFFSET = ErrCodeOffset(SUBSYS_NOTIFICATION);
constexpr int32_t ANS_NOTIFICATION_NOT_EXISTS = ANS_COMMON_ERR_OFFSET + 16;
constexpr int32_t ANS_ADMIN_SYSTEM_LIVE_VIEW_NOT_REMOVABLE = ANS_COMMON_ERR_OFFSET + 69;
constexpr int32_t ANS_ADMIN_NOTIFICATION_USER_DELETABLE_ONLY = ANS_COMMON_ERR_OFFSET + 70;
}

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<RemoveNotificationPlugin>());

RemoveNotificationPlugin::RemoveNotificationPlugin()
{
    policyCode_ = EdmInterfaceCode::REMOVE_NOTIFICATION;
    policyName_ = PolicyName::POLICY_REMOVE_NOTIFICATION;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NOTIFICATION,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode RemoveNotificationPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    std::string hashCode = data.ReadString();
    if (hashCode.empty()) {
        EDMLOGE("RemoveNotificationPlugin: hashCode is empty");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    EDMLOGI("RemoveNotificationPlugin OnHandlePolicy, admin=%{public}s", policyData.currentAdminName.c_str());
    int32_t ret = RemoveNotification(hashCode);
    if (ret == ERR_OK) {
        return ERR_OK;
    }
    EDMLOGE("RemoveNotificationPlugin: RemoveNotification failed, %{public}d", ret);
    if (ret == ANS_NOTIFICATION_NOT_EXISTS) {
        return EdmReturnErrCode::NOTIFICATION_NOT_EXIST;
    }
    if (ret == ANS_ADMIN_SYSTEM_LIVE_VIEW_NOT_REMOVABLE) {
        return EdmReturnErrCode::NOTIFICATION_SYSTEM_LIVE_VIEW_NOT_REMOVABLE;
    }
    if (ret == ANS_ADMIN_NOTIFICATION_USER_DELETABLE_ONLY) {
        return EdmReturnErrCode::NOTIFICATION_USER_DELETABLE_ONLY;
    }
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

int32_t RemoveNotificationPlugin::RemoveNotification(const std::string &hashCode)
{
    return OHOS::Notification::NotificationHelper::RemoveNotificationAsAdmin(hashCode);
}
} // namespace EDM
} // namespace OHOS
