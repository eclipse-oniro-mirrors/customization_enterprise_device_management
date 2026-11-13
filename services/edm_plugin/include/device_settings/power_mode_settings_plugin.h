/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_DEVICE_SETTINGS_POWER_MODE_SETTINGS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_DEVICE_SETTINGS_POWER_MODE_SETTINGS_PLUGIN_H

#include <cstdint>
#include <string>

#include <message_parcel.h>

#include "cJSON.h"
#include "external_manager_factory.h"
#include "iplugin.h"
#include "power_policy.h"

namespace OHOS {
namespace EDM {
class PowerModeSettingsPlugin : public IPlugin {
public:
    PowerModeSettingsPlugin(std::uint32_t policyCode, const std::string &policyName);

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override {};

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData,
        const std::string &mergeData, int32_t userId) override
    {
        return ERR_OK;
    };

    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData, int32_t userId)
        override {};

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

private:
    ErrCode DispatchSetPolicy(int32_t item, const std::string &valueStr);
    ErrCode DispatchGetPolicy(int32_t item, MessageParcel &reply);
    ErrCode SetScreenOffTime(const std::string &valueStr, const std::string &key);
    ErrCode GetScreenOffTime(MessageParcel &reply, bool isAc);
    ErrCode SetPowerPolicy(const std::string &valueStr, const std::string &key);
    ErrCode GetPowerPolicy(MessageParcel &reply, bool isAc);
    bool IsCrossUserNotAllowed(int32_t userId);
    bool ParsePowerPolicy(const std::string &valueStr, uint32_t &powerScene, PowerPolicy &powerPolicy);
    bool SetPowerPolicyObject(cJSON* root, const std::string &key, PowerPolicy &powerPolicy);
    bool GetPowerSceneKey(const uint32_t &powerScene, std::string &sceneKey);
    bool UpdateSuspendSettingsData(cJSON* root, const std::string &key, const std::string &suspendKey,
        const PowerPolicy &powerPolicy);
    bool DealPowerSuspendPolicy(const std::string &policyKey, const std::string &suspendKey,
        PowerPolicy &powerPolicy, bool isSetPolicy);
    std::string GetScreenOffTimeKey(bool isAc) const;
    std::string GetSuspendKey(bool isAc) const;
    std::shared_ptr<IExternalManagerFactory> externalManagerFactory_ = std::make_shared<ExternalManagerFactory>();
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_DEVICE_SETTINGS_POWER_MODE_SETTINGS_PLUGIN_H
