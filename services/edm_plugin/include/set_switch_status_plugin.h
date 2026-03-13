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
 
#ifndef SERVICES_EDM_PLUGIN_INCLUDE_SET_SWITCH_STATUS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_SET_SWITCH_STATUS_PLUGIN_H
 
#include "plugin_singleton.h"
#include "switch_param_serializer.h"
 
namespace OHOS {
namespace EDM {
class SetSwitchStatusPlugin : public PluginSingleton<SetSwitchStatusPlugin, SwitchParam> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<SetSwitchStatusPlugin, SwitchParam>> ptr) override;
    ErrCode OnSetPolicy(SwitchParam &param,  MessageParcel &reply);
    ErrCode OnSetBluetoothStatus(SwitchStatus status);
    ErrCode OnSetWifiStatus(SwitchStatus status);
    ~SetSwitchStatusPlugin();
};
} // namespace EDM
} // namespace OHOS
 
#endif // SERVICES_EDM_PLUGIN_INCLUDE_SET_SWITCH_STATUS_PLUGIN_H