/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EDM_PLUGIN_MANAGER_H
#define SERVICES_EDM_INCLUDE_EDM_PLUGIN_MANAGER_H

#include <dlfcn.h>
#include <map>
#include <memory>

#include "enhance_execute_strategy.h"
#include "iplugin.h"
#include "iplugin_execute_strategy.h"
#include "iplugin_manager.h"
#include "single_execute_strategy.h"

namespace OHOS {
namespace EDM {
class PluginManager : public std::enable_shared_from_this<PluginManager>, IPluginManager {
public:
    static std::shared_ptr<PluginManager> GetInstance();
    std::shared_ptr<IPlugin> GetPluginByFuncCode(std::uint32_t funcCode);
    std::shared_ptr<IPlugin> GetPluginByPolicyName(const std::string &policyName);
    bool AddPlugin(std::shared_ptr<IPlugin> plugin) override;
    bool AddExtensionPlugin(std::shared_ptr<IPlugin> extensionPlugin, uint32_t basicPluginCode,
        ExecuteStrategy strategy) override;
    virtual ~PluginManager();
    void Init();

    void DumpPlugin();
private:
    std::map<std::uint32_t, std::shared_ptr<IPlugin>> pluginsCode_;
    std::map<std::string, std::shared_ptr<IPlugin>> pluginsName_;
    std::map<std::uint32_t, std::uint32_t> extensionPluginMap_;
    std::map<std::uint32_t, ExecuteStrategy> executeStrategyMap_;
    std::vector<void *> pluginHandles_;
    static std::mutex mutexLock_;
    static std::shared_ptr<PluginManager> instance_;
    PluginManager();
    void LoadPlugin();
    void LoadPlugin(const std::string &pluginPath);
    std::shared_ptr<IPlugin> GetPluginByCode(std::uint32_t code);
    std::shared_ptr<IPluginExecuteStrategy> CreateExecuteStrategy(ExecuteStrategy strategy);
    std::shared_ptr<IPluginExecuteStrategy> enhanceStrategy_ = std::make_shared<EnhanceExecuteStrategy>();
    std::shared_ptr<IPluginExecuteStrategy> singleStrategy_ = std::make_shared<SingleExecuteStrategy>();
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_PLUGIN_MANAGER_H
