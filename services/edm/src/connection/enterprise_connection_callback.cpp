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

#include "enterprise_connection_callback.h"

#include "admin_manager.h"
#include "callback_strategies.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "edm_os_account_manager_impl.h"
#include "enterprise_admin_proxy.h"
#include "enterprise_conn_manager.h"
#include "external_manager_factory.h"

namespace OHOS {
namespace EDM {
EnterpriseConnectionCallback::EnterpriseConnectionCallback(const std::string& bundleName, int32_t userId)
    : bundleName_(bundleName), userId_(userId) {}

void EnterpriseConnectionCallback::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int32_t resultCode)
{
    if (resultCode != ERR_OK || remoteObject == nullptr) { // LCOV_EXCL_BR_LINE
        EDMLOGE("EnterpriseConnectionCallback::OnAbilityConnectDone failed: %{public}d", resultCode);
        auto manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
        if (manager) { // LCOV_EXCL_BR_LINE
            manager->RemoveRemoteObject(bundleName_, userId_);
        }
        return;
    }

    EDMLOGI("EnterpriseConnectionCallback::OnAbilityConnectDone bundle=%{public}s", bundleName_.c_str());

    sptr<EnterpriseAdminProxy> proxy = new (std::nothrow) EnterpriseAdminProxy(remoteObject);
    if (proxy == nullptr) { // LCOV_EXCL_BR_LINE
        EDMLOGE("EnterpriseConnectionCallback::OnAbilityConnectDone create proxy failed");
        auto manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
        if (manager) { // LCOV_EXCL_BR_LINE
            manager->RemoveRemoteObject(bundleName_, userId_);
        }
        return;
    }

    auto manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    if (manager) { // LCOV_EXCL_BR_LINE
        manager->SaveProxy(bundleName_, userId_, proxy);
    }
}

void EnterpriseConnectionCallback::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName& element, int32_t resultCode)
{
    EDMLOGI("EnterpriseConnectionCallback::OnAbilityDisconnectDone result: %{public}d", resultCode);

    // 先清理无效连接，避免后续使用无效proxy
    auto manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    if (manager == nullptr) { // LCOV_EXCL_BR_LINE
        return;
    }
    manager->RemoveRemoteObject(bundleName_, userId_);
    int32_t userId = std::make_shared<EdmOsAccountManagerImpl>()->GetCurrentUserId();
    if (userId < 0) { // LCOV_EXCL_BR_LINE
        EDMLOGW("EnterpriseConnectionCallback::OnAbilityDisconnectDone get userId failed.");
        return;
    }
    std::shared_ptr<Admin> admin =
        AdminManager::GetInstance()->GetAdminByPkgName(bundleName_, userId);
    if (admin && admin->IsEnterpriseAdminKeepAlive()) { // LCOV_EXCL_BR_LINE
#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
        CreateLogDirIfNeed(admin->adminInfo_.packageName_, userId);
#endif
        // StartStrategy触发连接建立，Execute方法为空仅用于触发连接
        auto strategy = std::make_shared<StartStrategy>();
        bool ret = manager->ExecuteCallback(admin->adminInfo_.packageName_, admin->adminInfo_.className_, userId,
            strategy);
        if (!ret) { // LCOV_EXCL_BR_LINE
            EDMLOGW("EnterpriseConnectionCallback::OnAbilityDisconnectDone ExecuteCallback failed.");
        }
    }
}

#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
void EnterpriseConnectionCallback::CreateLogDirIfNeed(const std::string &bundleName, int32_t userId)
{
    EDMLOGD("EnterpriseConnectionCallback::CreateLogDirIfNeed");
    std::shared_ptr<IExternalManagerFactory> factory = std::make_shared<ExternalManagerFactory>();
    if (!factory->CreateBundleManager()->IsBundleInstalled(bundleName, userId)) { // LCOV_EXCL_BR_LINE
        return;
    }
    std::string path = "/data/service/el1/public/edm/log/" + std::to_string(userId) + "/" + bundleName;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) && !ec) { // LCOV_EXCL_BR_LINE
        EDMLOGI("EnterpriseConnectionCallback::CreateLogDirIfNeed create log dir");
        if (!std::filesystem::create_directories(path, ec)) { // LCOV_EXCL_BR_LINE
            EDMLOGE("EnterpriseConnectionCallback create log dir fail. ec = %{public}d, %{public}s",
                ec.value(), ec.message().c_str());
        }
    }
}
#endif
} // namespace EDM
} // namespace OHOS