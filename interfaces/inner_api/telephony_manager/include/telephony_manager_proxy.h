/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_TELEPHONY_MANAGER_INCLUDE_TELEPHONY_MANAGER_PROXY_H
#define INTERFACES_INNER_API_TELEPHONY_MANAGER_INCLUDE_TELEPHONY_MANAGER_PROXY_H

#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
class TelephonyManagerProxy {
public:
    TelephonyManagerProxy();
    ~TelephonyManagerProxy();
    static std::shared_ptr<TelephonyManagerProxy> GetTelephonyManagerProxy();
    int32_t SetSimDisabled(MessageParcel &data);
    int32_t SetSimEnabled(MessageParcel &data);
    int32_t IsSimDisabled(MessageParcel &data, bool &result);
    int32_t AddCallPolicyNumbers(const AppExecFwk::ElementName &admin, const std::string &callType,
        const int32_t policyFlag, const std::vector<std::string> &numbers);
    int32_t RemoveCallPolicyNumbers(const AppExecFwk::ElementName &admin,
        const std::string &callType, const int32_t policyFlag, const std::vector<std::string> &numbers);
    int32_t GetCallPolicyNumbers(const AppExecFwk::ElementName &admin, const std::string &callType,
        const int32_t policyFlag, std::vector<std::string> &numbers);
private:
    static std::shared_ptr<TelephonyManagerProxy> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_TELEPHONY_MANAGER_INCLUDE_TELEPHONY_MANAGER_PROXY_H
