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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_DISALLOW_RANDOM_MAC_ADDRESS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_DISALLOW_RANDOM_MAC_ADDRESS_PLUGIN_H

#include "basic_bool_plugin.h"
#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {
class DisallowRandomMacAddressPlugin : public PluginSingleton<DisallowRandomMacAddressPlugin, bool>,
public BasicBoolPlugin {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<DisallowRandomMacAddressPlugin, bool>> ptr) override;
    ErrCode OnSetPolicy(bool &data, bool &currentData, bool &mergePolicy, int32_t userId) override;
};

private:
    ErrCode SetOtherModulePolicy(bool data, int32_t userId) override;
    // OHOS::sptr<OHOS::StorageManager::IStorageManager> GetStorageManager();
    // ErrCode UnmountStorageDevice();
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_DISALLOW_RANDOM_MAC_ADDRESS_PLUGIN_H