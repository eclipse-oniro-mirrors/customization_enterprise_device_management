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

#include "bundle_manager_utils.h"

#include <bundle_mgr_interface.h>
#include <ipc_skeleton.h>
#include <system_ability_definition.h>

#include "edm_log.h"
#include "edm_sys_manager.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "os_account_manager.h"
#endif

namespace OHOS {
namespace EDM {
ErrCode BundleManagerUtils::GetAppIdByCallingUid(std::string &appId)
{
#ifdef OS_ACCOUNT_EDM_ENABLE
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> bundleManager = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleManager == nullptr) {
        EDMLOGE("BundleManagerUtils::GetAppIdByCallingUid get bundleManager failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string callingBundleName;
    int32_t userId = 0;
    bundleManager->GetNameForUid(IPCSkeleton::GetCallingUid(), callingBundleName);
    if (FAILED(AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid(), userId))) {
        EDMLOGE("BundleManagerUtils::GetAppIdByCallingUid get userId failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    appId = bundleManager->GetAppIdByBundleName(callingBundleName, userId);
    return ERR_OK;
#else
    EDMLOGW("BundleManagerUtils::GetAppIdByCallingUid Unsupported Capabilities.");
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
#endif
}
} // namespace EDM
} // namespace OHOS