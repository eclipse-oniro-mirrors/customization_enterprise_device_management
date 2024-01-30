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
} // namespace EDM
} // namespace OHOS