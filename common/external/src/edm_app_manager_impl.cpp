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

#include "edm_app_manager_impl.h"

#include "system_ability_definition.h"

#include "edm_log.h"
#include "edm_sys_manager.h"

namespace OHOS {
namespace EDM {
ErrCode EdmAppManagerImpl::RegisterApplicationStateObserver(
    const sptr<AppExecFwk::IApplicationStateObserver>& observer)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    sptr<AppExecFwk::IAppMgr> proxy =  iface_cast<AppExecFwk::IAppMgr>(remoteObject);
    if (proxy && !proxy->RegisterApplicationStateObserver(observer)) {
        EDMLOGI("EdmAppManagerImpl::RegisterApplicationStateObserver success.");
        return ERR_OK;
    }
    EDMLOGE("EdmAppManagerImpl::RegisterApplicationStateObserver failed.");
    return ERR_APPLICATION_SERVICE_ABNORMALLY;
}

ErrCode EdmAppManagerImpl::UnregisterApplicationStateObserver(
    const sptr<AppExecFwk::IApplicationStateObserver>& observer)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    sptr<AppExecFwk::IAppMgr> proxy =  iface_cast<AppExecFwk::IAppMgr>(remoteObject);
    if (proxy && !proxy->UnregisterApplicationStateObserver(observer)) {
        EDMLOGI("EdmAppManagerImpl::UnregisterApplicationStateObserver success.");
        return ERR_OK;
    }
    EDMLOGE("EdmAppManagerImpl::UnregisterApplicationStateObserver failed.");
    return ERR_APPLICATION_SERVICE_ABNORMALLY;
}
} // namespace EDM
} // namespace OHOS