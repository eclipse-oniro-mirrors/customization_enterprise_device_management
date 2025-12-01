/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "edm_bundle_manager_impl.h"

#include "application_info.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_interface.h"
#include "system_ability_definition.h"

#include "edm_log.h"
#include "edm_sys_manager.h"

namespace OHOS {
namespace EDM {
ErrCode EdmBundleManagerImpl::GetNameForUid(int uid, std::string &name)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy && !proxy->GetNameForUid(uid, name)) {
        EDMLOGI("EdmBundleManagerImpl::GetNameForUid success.");
        return ERR_OK;
    }
    EDMLOGE("EdmBundleManagerImpl::GetNameForUid GetBundleMgr failed.");
    return ERR_BUNDLE_SERVICE_ABNORMALLY;
}

bool EdmBundleManagerImpl::QueryExtensionAbilityInfos(const AAFwk::Want &want,
    const AppExecFwk::ExtensionAbilityType &extensionType, int32_t flag, int32_t userId,
    std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy && proxy->QueryExtensionAbilityInfos(want, extensionType, flag, userId, extensionInfos)) {
        EDMLOGI("EdmBundleManagerImpl::QueryExtensionAbilityInfos success.");
        return true;
    }
    EDMLOGE("EdmBundleManagerImpl::QueryExtensionAbilityInfos GetBundleMgr failed.");
    return false;
}

bool EdmBundleManagerImpl::GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy && proxy->GetBundleInfo(bundleName, flag, bundleInfo, userId)) {
        EDMLOGI("EdmBundleManagerImpl::GetBundleInfo success.");
        return true;
    }
    EDMLOGE("EdmBundleManagerImpl::GetBundleInfo GetBundleMgr failed.");
    return false;
}

bool EdmBundleManagerImpl::GetBundleInfoV9(const std::string &bundleName, int32_t flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy && proxy->GetBundleInfoV9(bundleName, flag, bundleInfo, userId) == ERR_OK) {
        EDMLOGI("EdmBundleManagerImpl::GetBundleInfoV9 success.");
        return true;
    }
    EDMLOGE("EdmBundleManagerImpl::GetBundleInfoV9 GetBundleMgr failed.");
    return false;
}

bool EdmBundleManagerImpl::IsBundleInstalled(const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    bool isInstalled = false;
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("EdmBundleManagerImpl::GetBundleInfo GetBundleMgr failed.");
        return false;
    }
    if (FAILED(proxy->IsBundleInstalled(bundleName, userId, appIndex, isInstalled))) {
        EDMLOGW("EdmBundleManagerImpl::GetBundleInfo GetBundleMgr IsBundleInstalled failed.");
    }
    return isInstalled;
}

std::string EdmBundleManagerImpl::GetApplicationInfo(const std::string &appName, int userId)
{
    AppExecFwk::ApplicationInfo appInfo;
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("EdmBundleManagerImpl::GetApplicationInfo GetBundleMgr failed.");
        return "";
    }
    if (!proxy->GetApplicationInfo(appName, AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, appInfo)) {
        return "";
    }
    return appInfo.appDistributionType;
}

int32_t EdmBundleManagerImpl::GetApplicationUid(const std::string &appName, int userId, int appIndex)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("EdmBundleManagerImpl::GetApplicationUid GetBundleMgr failed.");
        return 0;
    }
    int32_t uid = proxy->GetUidByBundleName(appName, userId, appIndex);
    return uid;
}

int32_t EdmBundleManagerImpl::GetTokenId(const std::string &appName, int userId)
{
    AppExecFwk::ApplicationInfo appInfo;
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("EdmBundleManagerImpl::GetApplicationInfo GetBundleMgr failed.");
        return 0;
    }
    if (!proxy->GetApplicationInfo(appName, AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, appInfo)) {
        return 0;
    }
    return appInfo.accessTokenId;
}

ErrCode EdmBundleManagerImpl::AddAppInstallControlRule(std::vector<std::string> &data,
    AppExecFwk::AppInstallControlRuleType controlRuleType, int32_t userId)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("EdmBundleManagerImpl::AddAppInstallControlRule GetBundleMgr failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto appControlProxy = proxy->GetAppControlProxy();
    if (appControlProxy == nullptr) {
        EDMLOGE("EdmBundleManagerImpl::AddAppInstallControlRule GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode res = appControlProxy->AddAppInstallControlRule(data, controlRuleType, userId);
    if (res != ERR_OK) {
        EDMLOGE("EdmBundleManagerImpl AddAppInstallControlRule Faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode EdmBundleManagerImpl::DeleteAppInstallControlRule(AppExecFwk::AppInstallControlRuleType controlRuleType,
    std::vector<std::string> &data, int32_t userId)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("EdmBundleManagerImpl::DeleteAppInstallControlRule GetBundleMgr failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto appControlProxy = proxy->GetAppControlProxy();
    if (appControlProxy == nullptr) {
        EDMLOGE("EdmBundleManagerImpl::AddAppInstallControlRule GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode res = appControlProxy->DeleteAppInstallControlRule(controlRuleType, data, userId);
    if (res != ERR_OK) {
        EDMLOGE("EdmBundleManagerImpl DeleteAppInstallControlRule Faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool EdmBundleManagerImpl::SetDisallowedUninstall(const std::string &bundleName, bool state)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("EdmBundleManagerImpl::SwitchUninstallState GetBundleMgr failed.");
        return false;
    }
    if (FAILED(proxy->SwitchUninstallState(bundleName, !state, true))) {
        EDMLOGE("EdmBundleManagerImpl::%{public}s set disallow uninstall %{public}d fail.", bundleName.c_str(), state);
        return false;
    }
    EDMLOGI("EdmBundleManagerImpl::%{public}s set disallow uninstall %{public}d success.", bundleName.c_str(), state);
    return true;
}

bool EdmBundleManagerImpl::QueryAbilityInfo(const AAFwk::Want &want, int32_t flags,
    int32_t userId, AppExecFwk::AbilityInfo &abilityInfo)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy && proxy->QueryAbilityInfo(want, flags, userId, abilityInfo)) {
        EDMLOGI("EdmBundleManagerImpl::QueryAbilityInfo success.");
        return true;
    }
    EDMLOGE("EdmBundleManagerImpl::QueryAbilityInfo GetBundleMgr failed.");
    return false;
}

bool EdmBundleManagerImpl::QueryExtensionAbilityInfos(const AAFwk::Want &want, int32_t flag, int32_t userId,
    std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy && proxy->QueryExtensionAbilityInfos(want, flag, userId, extensionInfos)) {
        EDMLOGI("EdmBundleManagerImpl::QueryExtensionAbilityInfos success.");
        return true;
    }
    EDMLOGE("EdmBundleManagerImpl::QueryExtensionAbilityInfos GetBundleMgr failed.");
    return false;
}
} // namespace EDM
} // namespace OHOS