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

#ifndef COMMON_EXTERNAL_INCLUDE_EXTERNAL_MANAGER_FACTORY_H
#define COMMON_EXTERNAL_INCLUDE_EXTERNAL_MANAGER_FACTORY_H

#include "edm_access_token_manager_impl.h"
#include "edm_app_manager_impl.h"
#include "edm_bundle_manager_impl.h"
#include "edm_os_account_manager_impl.h"
#include "iexternal_manager_factory.h"

namespace OHOS {
namespace EDM {
class ExternalManagerFactory : public IExternalManagerFactory {
public:
    ~ExternalManagerFactory() override = default;
    std::shared_ptr<IEdmAppManager> CreateAppManager() override;
    std::shared_ptr<IEdmBundleManager> CreateBundleManager() override;
    std::shared_ptr<IEdmOsAccountManager> CreateOsAccountManager() override;
    std::shared_ptr<IEdmAccessTokenManager> CreateAccessTokenManager() override;

private:
    std::shared_ptr<IEdmAppManager> appMgr_ = std::make_shared<EdmAppManagerImpl>();
    std::shared_ptr<IEdmBundleManager> bundleMgr_ = std::make_shared<EdmBundleManagerImpl>();
    std::shared_ptr<IEdmOsAccountManager> osAccountMgr_ = std::make_shared<EdmOsAccountManagerImpl>();
    std::shared_ptr<IEdmAccessTokenManager> accessTokenMgr_ = std::make_shared<EdmAccessTokenManagerImpl>();
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_EXTERNAL_INCLUDE_IEXTERNAL_MANAGER_FACTORY_H