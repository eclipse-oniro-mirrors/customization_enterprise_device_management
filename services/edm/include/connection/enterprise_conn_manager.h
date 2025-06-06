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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_CONN_MANAGER_H
#define SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_CONN_MANAGER_H

#include <map>
#include <string>
#include <memory>

#include "ability_manager_interface.h"
#include "enterprise_account_connection.h"
#include "enterprise_admin_connection.h"
#include "enterprise_bundle_connection.h"
#include "enterprise_kiosk_connection.h"
#include "enterprise_update_connection.h"
#include "ienterprise_connection.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
class EnterpriseConnManager : public DelayedSingleton<EnterpriseConnManager> {
public:
    sptr<IEnterpriseConnection> CreateAdminConnection(const AAFwk::Want &want, uint32_t code, uint32_t userId,
        bool isOnAdminEnabled = true);
    sptr<IEnterpriseConnection> CreateBundleConnection(const AAFwk::Want &want, uint32_t code, uint32_t userId,
        const std::string &bundleName, int32_t accountId);
    sptr<IEnterpriseConnection> CreateUpdateConnection(const AAFwk::Want &want, uint32_t userId,
        const UpdateInfo &updateInfo);
    sptr<IEnterpriseConnection> CreateAccountConnection(const AAFwk::Want &want, uint32_t code, uint32_t userId,
        const int32_t accountId);
    sptr<IEnterpriseConnection> CreateKioskConnection(const AAFwk::Want &want, uint32_t code, uint32_t userId,
        const std::string &bundleName, int32_t accountId);
    bool ConnectAbility(const sptr<IEnterpriseConnection>& connection);
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_CONN_MANAGER_H