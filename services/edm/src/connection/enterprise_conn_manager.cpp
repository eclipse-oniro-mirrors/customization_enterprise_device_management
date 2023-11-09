/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "enterprise_conn_manager.h"

#include <if_system_ability_manager.h>
#include <ipc_skeleton.h>
#include <iservice_registry.h>
#include <string_ex.h>
#include <system_ability_definition.h>

#include "extension_manager_client.h"
#include "extension_manager_proxy.h"
#include "edm_log.h"
#include "managed_event.h"

using namespace OHOS::AAFwk;

namespace OHOS {
namespace EDM {
sptr<IEnterpriseConnection> EnterpriseConnManager::CreateAdminConnection(const AAFwk::Want &want,
    uint32_t code, uint32_t userId, bool isOnAdminEnabled)
{
    sptr<IEnterpriseConnection> connection(new (std::nothrow) EnterpriseAdminConnection(want, code, userId,
        isOnAdminEnabled));
    return connection;
}

sptr<IEnterpriseConnection> EnterpriseConnManager::CreateBundleConnection(const AAFwk::Want &want,
    uint32_t code, uint32_t userId, const std::string &bundleName)
{
    sptr<IEnterpriseConnection> connection(new (std::nothrow) EnterpriseBundleConnection(want,
        code, userId, bundleName));
    return connection;
}

sptr<IEnterpriseConnection> EnterpriseConnManager::CreateUpdateConnection(const AAFwk::Want &want,
    uint32_t userId, const UpdateInfo &updateInfo)
{
    sptr<IEnterpriseConnection> connection(new (std::nothrow)EnterpriseUpdateConnection(want,
        static_cast<uint32_t>(ManagedEvent::SYSTEM_UPDATE), userId, updateInfo));
    return connection;
}

bool EnterpriseConnManager::ConnectAbility(const sptr<IEnterpriseConnection>& connection)
{
    if (connection == nullptr) {
        return false;
    }
    int32_t ret = ExtensionManagerClient::GetInstance().ConnectEnterpriseAdminExtensionAbility(connection->GetWant(),
        connection, nullptr, connection->GetUserId());
    if (ret != ERR_OK) {
        EDMLOGE("EnterpriseConnManager::ConnectAbility connect extenison ability failed:%{public}d.", ret);
        return false;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS
