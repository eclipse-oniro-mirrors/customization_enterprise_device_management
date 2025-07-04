/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "set_allowed_kiosk_apps_plugin.h"

#include "ability_manager_client.h"
#include "array_string_serializer.h"
#include "bundle_mgr_interface.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "session_manager_lite.h"
#include "system_ability_definition.h"
#include "notification_helper.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetAllowedKioskAppsPlugin::GetPlugin());
const std::string KIOSK_APP_TRUST_LIST_KEY = "kiosk_app_trust_list";

void SetAllowedKioskAppsPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<SetAllowedKioskAppsPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("SetAllowedKioskAppsPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_KIOSK_APPS, PolicyName::POLICY_ALLOWED_KIOSK_APPS,
        EdmPermission::PERMISSION_ENTERPRISE_SET_KIOSK, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetAllowedKioskAppsPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&SetAllowedKioskAppsPlugin::OnAdminRemove);
    ptr->SetOtherServiceStartListener(&SetAllowedKioskAppsPlugin::OnOtherServiceStart);
}

ErrCode SetAllowedKioskAppsPlugin::OnSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    if (data.size() > EdmConstants::POLICIES_MAX_SIZE) {
        EDMLOGE("SetAllowedKioskAppsPlugin OnSetPolicy data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> bundleNames;
    ErrCode ret = convertAppIdentifierToBundleNames(data, bundleNames);
    if (FAILED(ret)) {
        EDMLOGE("SetAllowedKioskAppsPlugin convertAppIdentifierToBundleNames error.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ret = SetKioskAppsToAms(bundleNames);
    if (FAILED(ret)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ret = SetKioskAppsToWms(bundleNames);
    if (FAILED(ret)) {
        EDMLOGE("SetAllowedKioskAppsPlugin OnSetPolicy error clear");
        std::vector<std::string> emptyBundleNames;
        SetKioskAppsToAms(emptyBundleNames);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ret = SetKioskAppsToNotification(bundleNames);
    if (FAILED(ret)) {
        EDMLOGE("SetAllowedKioskAppsPlugin OnSetPolicy error clear");
        std::vector<std::string> emptyBundleNames;
        SetKioskAppsToAms(emptyBundleNames);
        SetKioskAppsToWms(emptyBundleNames);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

ErrCode SetAllowedKioskAppsPlugin::OnGetPolicy(
    std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::vector<std::string> appIdentifiers;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData, appIdentifiers);
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(appIdentifiers);
    return ERR_OK;
}

ErrCode SetAllowedKioskAppsPlugin::OnAdminRemove(
    const std::string &adminName, std::vector<std::string> &data, std::vector<std::string> &mergeData, int32_t userId)
{
    if (mergeData.empty()) {
        // merge is empty
        SetKioskAppsToAms(mergeData);
        SetKioskAppsToWms(mergeData);
        SetKioskAppsToNotification(mergeData);
    }
    return ERR_OK;
}

void SetAllowedKioskAppsPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("SetAllowedKioskAppsPlugin OnOtherServiceStart %{public}d", systemAbilityId);
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy(
        "", PolicyName::POLICY_ALLOWED_KIOSK_APPS, policyData, EdmConstants::DEFAULT_USER_ID);
    if (policyData.empty()) {
        EDMLOGI("SetAllowedKioskAppsPlugin OnOtherServiceStart policyData is empty");
        return;
    }
    std::vector<std::string> appIdentifiers;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData, appIdentifiers);
    std::vector<std::string> bundleNames;
    int32_t ret = convertAppIdentifierToBundleNames(appIdentifiers, bundleNames);
    if (FAILED(ret)) {
        return;
    }
    if (systemAbilityId == ABILITY_MGR_SERVICE_ID) {
        SetKioskAppsToAms(bundleNames);
    } else if (systemAbilityId == WINDOW_MANAGER_SERVICE_ID) {
        SetKioskAppsToWms(bundleNames);
    } else if (systemAbilityId == BUNDLE_MGR_SERVICE_SYS_ABILITY_ID) {
        SetKioskAppsToAms(bundleNames);
        SetKioskAppsToWms(bundleNames);
    }
}

int32_t SetAllowedKioskAppsPlugin::SetKioskAppsToAms(const std::vector<std::string> &bundleNames)
{
    EDMLOGI("SetAllowedKioskAppsPlugin SetKioskAppsToAms");
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        EDMLOGE("SetAllowedKioskAppsPlugin SetKioskAppsToAms can not get remoteObject");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = OHOS::AAFwk::AbilityManagerClient::GetInstance()->UpdateKioskApplicationList(bundleNames);
    if (FAILED(ret)) {
        EDMLOGE("SetAllowedKioskAppsPlugin SetKioskAppsToAms failed %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

int32_t SetAllowedKioskAppsPlugin::SetKioskAppsToWms(const std::vector<std::string> &bundleNames)
{
    EDMLOGI("SetAllowedKioskAppsPlugin SetKioskAppsToWms");
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(WINDOW_MANAGER_SERVICE_ID);
    if (remoteObject == nullptr) {
        EDMLOGE("SetAllowedKioskAppsPlugin SetKioskAppsToWms can not get remoteObject");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto wmsProxy = OHOS::Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    if (wmsProxy == nullptr) {
        EDMLOGE("SetAllowedKioskAppsPlugin SetKioskAppsToWms proxy is nullptr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto ret = wmsProxy->UpdateKioskAppList(bundleNames);
    if (ret != OHOS::Rosen::WMError::WM_OK) {
        EDMLOGE("SetAllowedKioskAppsPlugin SetKioskAppsToWms failed %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

int32_t SetAllowedKioskAppsPlugin::SetKioskAppsToNotification(const std::vector<std::string> &bundleNames)
{
    EDMLOGI("SetAllowedKioskAppsPlugin SetKioskAppsToNotification");
    std::string policyData;
    ArrayStringSerializer::GetInstance()->Serialize(bundleNames, policyData);
    int32_t ret = OHOS::Notification::NotificationHelper::SetAdditionConfig(KIOSK_APP_TRUST_LIST_KEY, policyData);
    if (FAILED(ret)) {
        EDMLOGE("SetAllowedKioskAppsPlugin SetKioskAppsToNotification failed %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

int32_t SetAllowedKioskAppsPlugin::convertAppIdentifierToBundleNames(
    const std::vector<std::string> &appIdentifiers, std::vector<std::string> &bundleNames)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    auto iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        EDMLOGE("SetAllowedKioskAppsPlugin convertAppIdentifierToBundleNames can not get iBundleMgr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bundleNames.clear();
    bundleNames.reserve(appIdentifiers.size());
    for (size_t i = 0; i < appIdentifiers.size(); ++i) {
        std::string bundleName;
        int32_t ret = iBundleMgr->GetBundleNameByAppId(appIdentifiers[i], bundleName);
        if (FAILED(ret)) {
            EDMLOGE("SetAllowedKioskAppsPlugin convertAppIdentifierToBundleNames failed %{public}d", ret);
            continue;
        }
        bundleNames.push_back(bundleName);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
