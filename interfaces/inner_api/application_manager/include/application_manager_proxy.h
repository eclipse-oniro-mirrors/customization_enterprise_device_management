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

#include "clear_up_application_data_param.h"
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
class ApplicationManagerProxy {
public:
    static std::shared_ptr<ApplicationManagerProxy> GetApplicationManagerProxy();
    int32_t AddDisallowedRunningBundles(AppExecFwk::ElementName &admin, std::vector<std::string> &bundles,
        int32_t userId, bool isSync = false);
    int32_t RemoveDisallowedRunningBundles(AppExecFwk::ElementName &admin, std::vector<std::string> &bundles,
        int32_t userId, bool isSync = false);
    int32_t GetDisallowedRunningBundles(AppExecFwk::ElementName &admin, int32_t userId,
        std::vector<std::string> &bundles, bool isSync = false);
    int32_t AddOrRemoveAutoStartApps(MessageParcel &data, bool isAdd);
    int32_t GetAutoStartApps(MessageParcel &data, std::vector<AppExecFwk::ElementName> &autoStartApps);
    int32_t RemoveKeepAliveApps(const AppExecFwk::ElementName &admin, const std::vector<std::string> &keepAliveApps,
        int32_t userId);
    int32_t GetKeepAliveApps(const AppExecFwk::ElementName &admin, std::vector<std::string> &keepAliveApps,
        int32_t userId);
    int32_t SetKioskFeatures(MessageParcel &data);
    int32_t ClearUpApplicationData(const AppExecFwk::ElementName &admin, const ClearUpApplicationDataParam &param);
    int32_t SetAllowedKioskApps(const AppExecFwk::ElementName &admin, const std::vector<std::string> &appIdentifiers);
    int32_t GetAllowedKioskApps(const AppExecFwk::ElementName &admin, std::vector<std::string> &appIdentifiers);
    int32_t IsAppKioskAllowed(const std::string &appIdentifier, bool &isAllowed);
    int32_t AddKeepAliveApps(const AppExecFwk::ElementName &admin, const std::vector<std::string> &keepAliveApps,
        bool disallowModify, int32_t userId, std::string &retMessage);
    int32_t IsModifyKeepAliveAppsDisallowed(const AppExecFwk::ElementName &admin, std::string &keepAliveApp,
        int32_t userId, bool &disallowModify);
    int32_t IsModifyAutoStartAppsDisallowed(MessageParcel &data, bool &isDisallowModify);
private:
    static std::shared_ptr<ApplicationManagerProxy> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_APPLICATION_MANAGER_PROXY_H
