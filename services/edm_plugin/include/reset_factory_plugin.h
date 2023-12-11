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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_RESET_FACTORY_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_RESET_FACTORY_PLUGIN_H

#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "string_serializer.h"
#include "system_ability_load_callback_stub.h"

namespace OHOS {
namespace EDM {
enum class LoadUpdaterSaStatus {
    WAIT_RESULT = 0,
    SUCCESS,
    FAIL,
};
class ResetFactoryPlugin : public PluginSingleton<ResetFactoryPlugin, std::string>,
    public SystemAbilityLoadCallbackStub {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<ResetFactoryPlugin, std::string>> ptr) override;
    void OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject) override;
    void OnLoadSystemAbilityFail(int32_t systemAbilityId) override;
    ErrCode OnSetPolicy();
    bool TryLoadUpdaterSa();
private:
    void InitStatus();
    void WaitUpdaterSaInit();
    bool CheckUpdaterSaLoaded();
    bool LoadUpdaterSa();

    LoadUpdaterSaStatus loadUpdaterSaStatus_ = LoadUpdaterSaStatus::WAIT_RESULT;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_RESET_FACTORY_PLUGIN_H