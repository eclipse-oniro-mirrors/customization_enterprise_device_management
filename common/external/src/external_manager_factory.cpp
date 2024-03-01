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

#include "external_manager_factory.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<IEdmAppManager> ExternalManagerFactory::CreateAppManager()
{
    return appMgr_;
}

std::shared_ptr<IEdmBundleManager> ExternalManagerFactory::CreateBundleManager()
{
    return bundleMgr_;
}

std::shared_ptr<IEdmOsAccountManager> ExternalManagerFactory::CreateOsAccountManager()
{
    return osAccountMgr_;
}

std::shared_ptr<IEdmAccessTokenManager> ExternalManagerFactory::CreateAccessTokenManager()
{
    return accessTokenMgr_;
}
} // namespace EDM
} // namespace OHOS