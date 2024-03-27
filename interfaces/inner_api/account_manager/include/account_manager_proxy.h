/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_ACCOUNT_MANAGER_INCLUDE_ACCOUNT_MANAGER_PROXY_H
#define INTERFACES_INNER_API_ACCOUNT_MANAGER_INCLUDE_ACCOUNT_MANAGER_PROXY_H

#include "enterprise_device_mgr_proxy.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "os_account_info.h"
#endif

namespace OHOS {
namespace EDM {
class AccountManagerProxy {
public:
    AccountManagerProxy();
    ~AccountManagerProxy();
    static std::shared_ptr<AccountManagerProxy> GetAccountManagerProxy();
    int32_t DisallowAddLocalAccount(AppExecFwk::ElementName &admin, bool isDisallow);
    int32_t IsAddLocalAccountDisallowed(AppExecFwk::ElementName *admin, bool &result);
    int32_t DisallowAddOsAccountByUser(AppExecFwk::ElementName &admin, int32_t userId, bool isDisallow);
    int32_t IsAddOsAccountByUserDisallowed(AppExecFwk::ElementName *admin, int32_t userId, bool &result);
#ifdef OS_ACCOUNT_EDM_ENABLE
    int32_t AddOsAccount(AppExecFwk::ElementName &admin, std::string name, int32_t type,
        OHOS::AccountSA::OsAccountInfo &accountInfo, std::string &distributedInfoName, std::string &distributedInfoId);
#endif

private:
    static std::shared_ptr<AccountManagerProxy> instance_;
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_ACCOUNT_MANAGER_INCLUDE_ACCOUNT_MANAGER_PROXY_H