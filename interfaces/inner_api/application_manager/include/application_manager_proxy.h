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

#ifndef INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_APPLICATION_MANAGER_PROXY_H
#define INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_APPLICATION_MANAGER_PROXY_H
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
class ApplicationManagerProxy {
public:
    static std::shared_ptr<ApplicationManagerProxy> GetApplicationManagerProxy();
    int32_t AddDisallowedRunningBundles(AppExecFwk::ElementName &admin, std::vector<std::string> &bundles,
        int32_t userId);
    int32_t RemoveDisallowedRunningBundles(AppExecFwk::ElementName &admin, std::vector<std::string> &bundles,
        int32_t userId);
    int32_t GetDisallowedRunningBundles(AppExecFwk::ElementName &admin, int32_t userId,
        std::vector<std::string> &bundles);
private:
    static std::shared_ptr<EnterpriseDeviceMgrProxy> proxy_;
    static std::shared_ptr<ApplicationManagerProxy> instance_;
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_APPLICATION_MANAGER_PROXY_H