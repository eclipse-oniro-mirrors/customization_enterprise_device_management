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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_USB_READ_ONLY_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_USB_READ_ONLY_PLUGIN_H

#include "plugin_singleton.h"
#include "istorage_manager.h"

namespace OHOS {
namespace EDM {
class UsbReadOnlyPlugin : public PluginSingleton<UsbReadOnlyPlugin, int32_t> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<UsbReadOnlyPlugin, int32_t>> ptr) override;

    ErrCode SetPolicy(int32_t &policyValue);
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
    ErrCode OnAdminRemove(const std::string &adminName, int32_t &data, int32_t userId);
private:
    OHOS::sptr<OHOS::StorageManager::IStorageManager> GetStorageManager();
    ErrCode ReloadUsbDevice();
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_USB_READ_ONLY_PLUGIN_H
