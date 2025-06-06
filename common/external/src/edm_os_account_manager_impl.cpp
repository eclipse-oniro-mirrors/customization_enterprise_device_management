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

#include "edm_os_account_manager_impl.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
ErrCode EdmOsAccountManagerImpl::QueryActiveOsAccountIds(std::vector<int32_t> &ids)
{
#ifdef OS_ACCOUNT_EDM_ENABLE
    return AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
#else
    EDMLOGW("EdmOsAccountManagerImpl::QueryActiveOsAccountIds Unsupported Capabilities.");
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
#endif
}

ErrCode EdmOsAccountManagerImpl::IsOsAccountExists(int32_t id, bool &isExist)
{
#ifdef OS_ACCOUNT_EDM_ENABLE
    return AccountSA::OsAccountManager::IsOsAccountExists(id, isExist);
#else
    EDMLOGW("EdmOsAccountManagerImpl::IsOsAccountExists Unsupported Capabilities.");
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
#endif
}

#ifdef OS_ACCOUNT_EDM_ENABLE
ErrCode EdmOsAccountManagerImpl::CreateOsAccount(const std::string &name, const OHOS::AccountSA::OsAccountType &type,
    OHOS::AccountSA::OsAccountInfo &osAccountInfo)
{
    EDMLOGI("EdmOsAccountManagerImpl::CreateOsAccount.");
    return OHOS::AccountSA::OsAccountManager::CreateOsAccount(name, type, osAccountInfo);
}
#endif
} // namespace EDM
} // namespace OHOS