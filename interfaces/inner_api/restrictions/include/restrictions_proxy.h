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

#ifndef INTERFACES_INNER_API_RESTRICTIONS_INCLUDE_RESTRICTIONS_PROXY_H
#define INTERFACES_INNER_API_RESTRICTIONS_INCLUDE_RESTRICTIONS_PROXY_H
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
class RestrictionsProxy {
public:
    static std::shared_ptr<RestrictionsProxy> GetRestrictionsProxy();
    int32_t SetPrinterDisabled(const AppExecFwk::ElementName &admin, bool isDisabled);
    int32_t SetHdcDisabled(const AppExecFwk::ElementName &admin, bool isDisabled);
    int32_t IsPrinterDisabled(AppExecFwk::ElementName *admin, bool &result);
    int32_t IsHdcDisabled(AppExecFwk::ElementName *admin, bool &result);
    int32_t DisallowScreenShot(const AppExecFwk::ElementName &admin, bool isDisabled);
    int32_t IsScreenShotDisallowed(AppExecFwk::ElementName *admin, bool &result);
    int32_t DisableMicrophone(const AppExecFwk::ElementName &admin, bool disable);
    int32_t IsMicrophoneDisabled(AppExecFwk::ElementName *admin, bool &result);

private:
    static std::shared_ptr<RestrictionsProxy> instance_;
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_RESTRICTIONS_INCLUDE_RESTRICTIONS_PROXY_H