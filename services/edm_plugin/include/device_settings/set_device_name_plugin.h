/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_SET_DEVICE_NAME_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_SET_DEVICE_NAME_PLUGIN_H

#include "external_manager_factory.h"
#include "plugin_singleton.h"

#ifdef WIFI_EDM_ENABLE
#include "inner_api/wifi_hotspot.h"
#include "wifi_device.h"
#endif

namespace OHOS {
namespace EDM {
class SetDeviceNamePlugin : public PluginSingleton<SetDeviceNamePlugin, std::string> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<SetDeviceNamePlugin, std::string>> ptr) override;
    ErrCode OnSetPolicy(std::string &data, std::string &currentData, std::string &mergeData, int32_t userId);
    ErrCode OnGetPolicy(std::string &value, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
private:
    std::shared_ptr<IExternalManagerFactory> externalManagerFactory_ = std::make_shared<ExternalManagerFactory>();
#if defined(TELEPHONY_EDM_ENABLE) && defined(WIFI_EDM_ENABLE)
    ErrCode UpdateHotspotNameIfNeed(const std::string &value, int32_t userId);
    ErrCode PrepareHotspotConfig(const std::string &value, Wifi::HotspotConfig &hotspotConfig, bool &needUpdate);
    ErrCode ApplyHotspotConfig(Wifi::WifiHotspot *hotspot, const Wifi::HotspotConfig &hotspotConfig);
    ErrCode UpdateHotspotName(const std::string &value);
    std::string GetSubstringByBytes(const std::string &value, size_t size);
#endif
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_SET_DEVICE_NAME_PLUGIN_H