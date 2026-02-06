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

#include "edm_constants.h"
#include "enterprise_device_mgr_proxy.h"
#include "power_policy.h"
#include "setting_item_policy.h"

namespace OHOS {
namespace EDM {
class DeviceSettingsProxy {
public:
    static std::shared_ptr<DeviceSettingsProxy> GetDeviceSettingsProxy();
    int32_t SetScreenOffTime(const AppExecFwk::ElementName &admin, int32_t value,
        const std::string &permissionTag = EdmConstants::PERMISSION_TAG_VERSION_11);
    int32_t SetScreenOffTime(MessageParcel &data);
    int32_t GetScreenOffTime(const AppExecFwk::ElementName &admin, int32_t &value,
        const std::string &permissionTag = EdmConstants::PERMISSION_TAG_VERSION_11);
    int32_t GetScreenOffTime(MessageParcel &data, int32_t &value);
    int32_t InstallUserCertificate(MessageParcel &data, std::string &result, std::string &innerCodeMsg);
    int32_t UninstallUserCertificate(MessageParcel &data, std::string &innerCodeMsg);
    int32_t SetPowerPolicy(const AppExecFwk::ElementName &admin, const PowerScene &powerScene,
        const PowerPolicy &powerPolicy);
    int32_t SetPowerPolicy(MessageParcel &data);
    int32_t GetPowerPolicy(const AppExecFwk::ElementName &admin, const PowerScene &powerScene,
        PowerPolicy &powerPolicy);
    int32_t GetPowerPolicy(MessageParcel &data, PowerPolicy &powerPolicy);
    int32_t SetWallPaper(MessageParcel &data, std::string &errMsg);
    int32_t SetEyeComfortMode(const AppExecFwk::ElementName &admin, const std::string &value);
    int32_t GetEyeComfortMode(const AppExecFwk::ElementName &admin, std::string &value);
    int32_t SetDefaultInputMethod(const AppExecFwk::ElementName &admin, const std::string &value);
    int32_t SetValueForAccount(const AppExecFwk::ElementName &admin, int32_t accountId, const std::string &value,
        const std::string &permissionTag = EdmConstants::PERMISSION_TAG_VERSION_23);
    int32_t GetValueForAccount(const AppExecFwk::ElementName &admin, int32_t accountId, std::string &value,
        const std::string &permissionTag = EdmConstants::PERMISSION_TAG_VERSION_23);
    int32_t DeviceSettingsProxy::SetFloatingNavigationForAccount(const AppExecFwk::ElementName &admin,
        int32_t accountId, const std::string &value);
    int32_t DeviceSettingsProxy::GetFloatingNavigationForAccount(const AppExecFwk::ElementName &admin,
        int32_t accountId, std::string &value);

private:
    static std::shared_ptr<DeviceSettingsProxy> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_DEVICE_SETTINGS_PROXY_H
