/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "enterprise_admin_connection.h"

#include "admin_manager.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "edm_os_account_manager_impl.h"
#include "enterprise_conn_manager.h"

namespace OHOS {
namespace EDM {
EnterpriseAdminConnection::~EnterpriseAdminConnection() {}

void EnterpriseAdminConnection::SetIsOnAdminEnabled(bool isOnAdminEnabled)
{
    isOnAdminEnabled_ = isOnAdminEnabled;
}

void EnterpriseAdminConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int32_t resultCode)
{
    EDMLOGI("EnterpriseAdminConnection OnAbilityConnectDone");
    proxy_ = (new (std::nothrow) EnterpriseAdminProxy(remoteObject));
    if (!proxy_) {
        EDMLOGE("EnterpriseAdminConnection get enterpriseAdminProxy failed.");
        return;
    }
    switch (code_) {
        case IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED:
            if (isOnAdminEnabled_) {
                proxy_->OnAdminEnabled();
            }
            break;
        case IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED:
            proxy_->OnAdminDisabled();
            break;
        case IEnterpriseAdmin::COMMAND_ON_DEVICE_ADMIN_ENABLED:
            proxy_->OnDeviceAdminEnabled(bundleName_);
            break;
        case IEnterpriseAdmin::COMMAND_ON_DEVICE_ADMIN_DISABLED:
            proxy_->OnDeviceAdminDisabled(bundleName_);
            break;
        default:
            return;
    }
    EDMLOGI("EnterpriseAdminConnection OnAbilityConnectDone over");
}

void EnterpriseAdminConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int32_t resultCode)
{
    EDMLOGI("EnterpriseAdminConnection OnAbilityDisconnectDone");
    int32_t userId = GetCurrentUserId();
    if (userId < 0) {
        EDMLOGW("EnterpriseAdminConnection::OnAbilityDisconnectDone get userId failed.");
        return;
    }
    std::shared_ptr<Admin> admin =
        AdminManager::GetInstance()->GetAdminByPkgName(want_.GetElement().GetBundleName(), userId);
    if (admin && admin->IsEnterpriseAdminKeepAlive()) {
#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
        std::string bundleName = admin->adminInfo_.packageName_;
        std::string path = "/data/service/el1/public/edm/log/" + std::to_string(userId) + "/" + bundleName;
        if (!std::filesystem::exists(path)) {
            EDMLOGI("EnterpriseAdminConnection::OnAbilityDisconnectDone create log dir");
            if (!std::filesystem::create_directories(path)) {
                EDMLOGE("EnterpriseAdminConnection::OnAbilityDisconnectDone create log dir fail.");
            }
        }
#endif
        std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
        bool ret = manager->CreateAdminConnection(want_, IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, userId, false);
        if (!ret) {
            EDMLOGW("EnterpriseAdminConnection::OnAbilityDisconnectDone CreateAdminConnection failed.");
        }
    }
}

int32_t EnterpriseAdminConnection::GetCurrentUserId()
{
    std::vector<int32_t> ids;
    ErrCode ret = std::make_shared<EdmOsAccountManagerImpl>()->QueryActiveOsAccountIds(ids);
    if (FAILED(ret) || ids.empty()) {
        EDMLOGE("EnterpriseAdminConnection GetCurrentUserId failed");
        return -1;
    }
    EDMLOGD("EnterpriseAdminConnection GetCurrentUserId");
    return (ids.at(0));
}
}  // namespace EDM
}  // namespace OHOS
