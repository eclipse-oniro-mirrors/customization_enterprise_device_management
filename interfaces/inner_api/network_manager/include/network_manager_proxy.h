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

#ifndef INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_NETWORK_MANAGER_PROXY_H
#define INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_NETWORK_MANAGER_PROXY_H

#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
class NetworkManagerProxy {
public:
    NetworkManagerProxy();
    ~NetworkManagerProxy();
    static std::shared_ptr<NetworkManagerProxy> GetNetworkManagerProxy();
    int32_t GetAllNetworkInterfaces(const AppExecFwk::ElementName &admin, std::vector<std::string> &networkInterface);
    int32_t GetIpOrMacAddress(const AppExecFwk::ElementName &admin, const std::string &networkInterface,
        int policyCode, std::string &info);
    int32_t SetNetworkInterfaceDisabled(const AppExecFwk::ElementName &admin, const std::string &networkInterface,
        bool isDisabled);
    int32_t IsNetworkInterfaceDisabled(const AppExecFwk::ElementName &admin, const std::string &networkInterface,
        bool &status);
private:
    static std::shared_ptr<EnterpriseDeviceMgrProxy> proxy_;
    static std::shared_ptr<NetworkManagerProxy> instance_;
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_NETWORK_MANAGER_PROXY_H
