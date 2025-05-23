/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_BROWSER_INCLUDE_BROWSER_PROXY_H
#define INTERFACES_INNER_API_BROWSER_INCLUDE_BROWSER_PROXY_H

#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
class BrowserProxy {
public:
    static std::shared_ptr<BrowserProxy> GetBrowserProxy();
    int32_t GetPolicies(AppExecFwk::ElementName &admin, const std::string &appId, std::string &policies);
    int32_t GetPolicies(std::string &policies);
    int32_t SetPolicy(const AppExecFwk::ElementName &admin, const std::string &appId, const std::string &policyName,
        const std::string &policyValue);
    int32_t SetManagedBrowserPolicy(MessageParcel &data);
    int32_t GetManagedBrowserPolicy(MessageParcel &data, void** rawData, int32_t &size);
    int32_t GetSelfManagedBrowserPolicyVersion(int32_t &version);
    int32_t GetSelfManagedBrowserPolicy(void** rawData, int32_t &size);

private:
    int32_t GetPolicies(AppExecFwk::ElementName *admin, const std::string &appId, std::string &policies);
    int32_t GetRawData(MessageParcel& reply, void** rawData, int32_t& size);
    static std::shared_ptr<BrowserProxy> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_BROWSER_INCLUDE_BROWSER_PROXY_H