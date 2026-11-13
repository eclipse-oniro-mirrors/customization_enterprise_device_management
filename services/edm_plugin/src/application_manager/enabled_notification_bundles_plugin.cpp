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

#include "enabled_notification_bundles_plugin.h"

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "notification_helper.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(EnabledNotificationBundlesPlugin::GetPlugin());

void EnabledNotificationBundlesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<EnabledNotificationBundlesPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("EnabledNotificationBundlesPlugin InitPlugin");
    ptr->InitAttribute(EdmInterfaceCode::ENABLED_NOTIFICATION_BUNDLES,
        PolicyName::POLICY_ENABLED_NOTIFICATION_BUNDLES,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NOTIFICATION,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&EnabledNotificationBundlesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&EnabledNotificationBundlesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&EnabledNotificationBundlesPlugin::OnAdminRemove);
}

ErrCode EnabledNotificationBundlesPlugin::OnSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGI("EnabledNotificationBundlesPlugin OnSetPolicy, userId=%{public}d", userId);
    if (userId <= 0) {
        EDMLOGE("EnabledNotificationBundlesPlugin OnSetPolicy invalid userId=%{public}d", userId);
        return EdmReturnErrCode::UID_INVALID;
    }
    if (data.empty()) {
        EDMLOGW("EnabledNotificationBundlesPlugin OnSetPolicy data is empty");
        return ERR_OK;
    }
    if (data.size() > EdmConstants::NOTIFICATION_BUNDLES_MAX_SIZE) {
        EDMLOGE("EnabledNotificationBundlesPlugin OnSetPolicy input oversize=%{public}zu", data.size());
        return EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    }
    auto serializer = ArrayStringSerializer::GetInstance();
    std::vector<std::string> afterHandle = serializer->SetUnionPolicyData(currentData, data);
    std::vector<std::string> afterMerge = serializer->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > EdmConstants::NOTIFICATION_BUNDLES_MAX_SIZE) {
        EDMLOGE("EnabledNotificationBundlesPlugin OnSetPolicy merge oversize=%{public}zu", afterMerge.size());
        return EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    }
    ErrCode ret = PushMergedList(afterMerge, userId);
    if (ret != ERR_OK) {
        return ret;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode EnabledNotificationBundlesPlugin::OnRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGI("EnabledNotificationBundlesPlugin OnRemovePolicy, userId=%{public}d", userId);
    if (userId <= 0) {
        EDMLOGE("EnabledNotificationBundlesPlugin OnRemovePolicy invalid userId=%{public}d", userId);
        return EdmReturnErrCode::UID_INVALID;
    }
    if (data.empty()) {
        EDMLOGW("EnabledNotificationBundlesPlugin OnRemovePolicy data is empty");
        return ERR_OK;
    }
    if (data.size() > EdmConstants::NOTIFICATION_BUNDLES_MAX_SIZE) {
        EDMLOGE("EnabledNotificationBundlesPlugin OnRemovePolicy input oversize=%{public}zu", data.size());
        return EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    }
    auto serializer = ArrayStringSerializer::GetInstance();
    std::vector<std::string> needRemove = serializer->SetIntersectionPolicyData(data, currentData);
    std::vector<std::string> afterHandle = serializer->SetDifferencePolicyData(needRemove, currentData);
    std::vector<std::string> afterMerge = serializer->SetUnionPolicyData(mergeData, afterHandle);
    ErrCode ret = PushMergedList(afterMerge, userId);
    if (ret != ERR_OK) {
        return ret;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode EnabledNotificationBundlesPlugin::OnAdminRemove(const std::string &adminName,
    std::vector<std::string> &data, std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGI("EnabledNotificationBundlesPlugin OnAdminRemove, userId=%{public}d", userId);
    if (userId <= 0) {
        EDMLOGE("EnabledNotificationBundlesPlugin OnAdminRemove invalid userId=%{public}d", userId);
        return EdmReturnErrCode::UID_INVALID;
    }
    ErrCode ret = PushMergedList(mergeData, userId);
    if (ret != ERR_OK) {
        EDMLOGE("EnabledNotificationBundlesPlugin OnAdminRemove push failed, ret=%{public}d, userId=%{public}d",
            ret, userId);
    }
    return ret;
}

ErrCode EnabledNotificationBundlesPlugin::PushMergedList(const std::vector<std::string> &mergeData, int32_t userId)
{
    int32_t ret = Notification::NotificationHelper::SetSilentAuthNotificationInfo(mergeData, userId);
    if (ret != ERR_OK) {
        EDMLOGE("EnabledNotificationBundlesPlugin SetSilentAuthNotificationInfo failed, ret=%{public}d, "
            "userId=%{public}d, size=%{public}zu", ret, userId, mergeData.size());
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    EDMLOGI("EnabledNotificationBundlesPlugin push list, userId=%{public}d, size=%{public}zu",
        userId, mergeData.size());
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
