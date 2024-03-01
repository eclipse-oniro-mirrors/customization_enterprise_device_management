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

#ifndef COMMON_EXTERNAL_INCLUDE_IEXTERNAL_MANAGER_FACTORY_H
#define COMMON_EXTERNAL_INCLUDE_IEXTERNAL_MANAGER_FACTORY_H

#include <memory>

#include "iedm_access_token_manager.h"
#include "iedm_app_manager.h"
#include "iedm_bundle_manager.h"
#include "iedm_os_account_manager.h"

namespace OHOS {
namespace EDM {
class IExternalManagerFactory {
public:
    virtual ~IExternalManagerFactory() = default;
    virtual std::shared_ptr<IEdmAppManager> CreateAppManager() = 0;
    virtual std::shared_ptr<IEdmBundleManager> CreateBundleManager() = 0;
    virtual std::shared_ptr<IEdmOsAccountManager> CreateOsAccountManager() = 0;
    virtual std::shared_ptr<IEdmAccessTokenManager> CreateAccessTokenManager() = 0;
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_EXTERNAL_INCLUDE_IEXTERNAL_MANAGER_FACTORY_H