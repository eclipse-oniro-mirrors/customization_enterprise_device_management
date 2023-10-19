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

#ifndef INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_DEVICE_SETTINGS_PROXY_H
#define INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_DEVICE_SETTINGS_PROXY_H
#include "enterprise_device_mgr_proxy.h"
#include "power_policy.h"

namespace OHOS {
namespace EDM {
class DeviceSettingsProxy {
public:
    static std::shared_ptr<DeviceSettingsProxy> GetDeviceSettingsProxy();
    int32_t SetScreenOffTime(const AppExecFwk::ElementName &admin, int32_t value);
    int32_t GetScreenOffTime(const AppExecFwk::ElementName &admin, int32_t &value);
    int32_t InstallUserCertificate(const AppExecFwk::ElementName &admin, const std::vector<uint8_t> &certArray,
        std::string &alias, std::string &result, std::string &innerCodeMsg);
    int32_t UninstallUserCertificate(const AppExecFwk::ElementName &admin, const std::string &certUri,
        std::string &innerCodeMsg);
    int32_t SetPowerPolicy(const AppExecFwk::ElementName &admin, const PowerScene &powerScene,
        const PowerPolicy &powerPolicy);
    int32_t GetPowerPolicy(const AppExecFwk::ElementName &admin, const PowerScene &powerScene,
        PowerPolicy &powerPolicy);

private:
    static std::shared_ptr<DeviceSettingsProxy> instance_;
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_DEVICE_SETTINGS_PROXY_H
