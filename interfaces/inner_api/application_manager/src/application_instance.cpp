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

#include "application_instance.h"
#include "edm_log.h"
#include "edm_constants.h"
#include "edm_sys_manager.h"
#include "bundle_mgr_interface.h"
#include "iedm_bundle_manager.h"
#include "edm_bundle_manager_impl.h"

namespace OHOS {
namespace EDM {
const int BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401;

std::string ApplicationInstanceHandle::GetAppIdentifierByBundleName(std::string bundleName, int32_t accountId)
{
    std::string appIdentifier;
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    AppExecFwk::BundleInfo bundleInfo;
    bool res = bundleMgr->GetBundleInfo(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, accountId);
    if (!res) {
        return "";
    }
    appIdentifier = bundleInfo.signatureInfo.appIdentifier;
    return appIdentifier;
}

bool ApplicationInstanceHandle::GetBundleNameByAppId(ApplicationInstance &appInstance)
{
    std::string bundleName;
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("ApplicationInstanceHandle GetBundleNameByAppId appControlProxy failed.");
        return false;
    }
    ErrCode res = proxy->GetBundleNameByAppId(appInstance.appIdentifier, bundleName);
    if (res != ERR_OK) {
        EDMLOGE("ApplicationInstanceHandle GetBundleNameByAppId failed.");
        return false;
    }
    appInstance.bundleName = bundleName;
    return true;
}

bool ApplicationInstanceHandle::WriteApplicationInstance(MessageParcel &data, const ApplicationInstance appInstance)
{
    if (!data.WriteString(appInstance.appIdentifier)) {
        return false;
    }
    if (!data.WriteString(appInstance.bundleName)) {	
        return false;
    }
    if (!data.WriteInt32(appInstance.accountId)) {
        return false;
    }
    if (!data.WriteInt32(appInstance.appIndex)) {
        return false;
    }
    return true;
}

bool ApplicationInstanceHandle::WriteApplicationInstanceVector(MessageParcel &data,
    const std::vector<ApplicationInstance> freezeExemptedApps)
{
    if (!data.WriteInt32(freezeExemptedApps.size())) {
        return false;
    }

    for (const auto &appInstance : freezeExemptedApps) {
        if (!WriteApplicationInstance(data, appInstance)) {
            return false;
        }
    }
    return true;
}

bool ApplicationInstanceHandle::ReadApplicationInstance(MessageParcel &data, ApplicationInstance &appInstance)
{
    if (!data.ReadString(appInstance.appIdentifier)) {
        return false;
    }
    if (!data.ReadString(appInstance.bundleName)) {
        return false;
    }
    if (!data.ReadInt32(appInstance.accountId)) {
        return false;
    }
    if (!data.ReadInt32(appInstance.appIndex)) {
        return false;
    }
    return true;
}

bool ApplicationInstanceHandle::ReadApplicationInstanceVector(MessageParcel &data,
    std::vector<ApplicationInstance> &freezeExemptedApps)
{
    int32_t size = data.ReadInt32();
    if (size < 0 || size > EdmConstants::MANAGE_APPS_MAX_SIZE) {
        return false;
    }
    freezeExemptedApps.clear();
    freezeExemptedApps.reserve(size);

    for (int32_t i = 0; i < size; i++) {
        ApplicationInstance instance;
        if (!ReadApplicationInstance(data, instance)) {
            return false;
        }
        freezeExemptedApps.emplace_back(std::move(instance));
    }
    return true;
}
} // namespace EDM
} // namespace OHOS