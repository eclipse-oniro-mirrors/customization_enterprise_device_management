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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_ADDDISALLOWEDRUNNINGBUNDLES_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_ADDDISALLOWEDRUNNINGBUNDLES_PLUGIN_H

#include <vector>

#include "bundle_mgr_interface.h"

#include "basic_array_string_plugin.h"
#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {
class DisallowedRunningBundlesPlugin : public PluginSingleton<DisallowedRunningBundlesPlugin,
    std::vector<std::string>>, public BasicArrayStringPlugin {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<DisallowedRunningBundlesPlugin,
        std::vector<std::string>>> ptr) override;

private:
    ErrCode SetOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
        std::vector<std::string> &failedData) override;
    ErrCode RemoveOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
        std::vector<std::string> &failedData) override;

    sptr<AppExecFwk::IAppControlMgr> GetAppControlProxy();
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_ADDDISALLOWEDRUNNINGBUNDLES_PLUGIN_H
