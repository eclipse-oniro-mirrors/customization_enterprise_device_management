/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <shared_mutex>
#include <thread>

#include "enhance_execute_strategy.h"
#include "iplugin.h"
#include "iplugin_execute_strategy.h"
#include "iplugin_manager.h"
#include "replace_execute_strategy.h"
#include "single_execute_strategy.h"

namespace OHOS {
namespace EDM {
struct SoLoadState {
    bool pluginHasInit = false;
    std::mutex waitMutex;
    bool notifySignal = false;
    std::condition_variable waitSignal;
    std::chrono::system_clock::time_point lastCallTime;
    void* pluginHandles;
};
namespace SONAME {
const char* const DEVICE_CORE_PLUGIN_SO = "libdevice_core_plugin.z.so";
const char* const COMMUNICATION_PLUGIN_SO = "libcommunication_plugin.z.so";
const char* const SYS_SERVICE_PLUGIN_SO = "libsys_service_plugin.z.so";
const char* const NEED_EXTRA_PLUGIN_SO = "libneed_extra_plugin.z.so";
const char* const OLD_EDM_PLUGIN_SO = "libedmplugin.z.so";
}

class PluginManager : public std::enable_shared_from_this<PluginManager>, IPluginManager {
public:
    static std::shared_ptr<PluginManager> GetInstance();
    std::shared_ptr<IPlugin> GetPluginByFuncCode(std::uint32_t funcCode);
    std::shared_ptr<IPlugin> GetPluginByPolicyName(const std::string &policyName);
    bool AddPlugin(std::shared_ptr<IPlugin> plugin) override;
    bool AddExtensionPlugin(std::shared_ptr<IPlugin> extensionPlugin, uint32_t basicPluginCode,
        ExecuteStrategy strategy) override;
    virtual ~PluginManager();
    
    void LoadAllPlugin();
    void LoadPluginByCode(uint32_t code);
    void LoadPluginByFuncCode(uint32_t funcCode);
    void DumpPlugin();
    void NotifyUnloadAllPlugin();

private:
    std::map<std::uint32_t, std::shared_ptr<IPlugin>> pluginsCode_;
    std::map<std::string, std::shared_ptr<IPlugin>> pluginsName_;
    std::map<std::uint32_t, std::uint32_t> extensionPluginMap_;
    std::map<std::uint32_t, ExecuteStrategy> executeStrategyMap_;
    std::unordered_map<std::string, std::shared_ptr<SoLoadState>> soLoadStateMap_;
    static std::vector<uint32_t> deviceCoreSoCodes_;
    static std::vector<uint32_t> communicationSoCodes_;
    static std::vector<uint32_t> sysServiceSoCodes_;
    static std::vector<uint32_t> needExtraSoCodes_;
    
    static std::shared_timed_mutex mutexLock_;
    static std::shared_ptr<PluginManager> instance_;
    PluginManager();
    void DlopenPlugin(const std::string &pluginPath, std::shared_ptr<SoLoadState> loadStatePtr);
    void LoadPlugin(const std::string &soName);
    void UnloadPlugin(const std::string &soName);
    void LoadExtraPlugin();
    bool IsExtraPlugin(const std::string &soName);
    void UnloadPluginTask(const std::string &soName, std::shared_ptr<SoLoadState> loadStatePtr);
    void RemovePlugin(std::shared_ptr<IPlugin> plugin);
    bool GetSoNameByCode(std::uint32_t code, std::string &soName);
    void GetExtraPluginCodeList(std::vector<uint32_t>* targetVec);
    bool AddPluginInner(std::shared_ptr<IPlugin> plugin);
    void DumpPluginInner(std::map<std::uint32_t, std::shared_ptr<IPlugin>> pluginsCode,
        std::map<std::string, std::shared_ptr<IPlugin>> pluginsName);
    void DumpPluginConfig(IPlugin::PolicyPermissionConfig config);
    std::shared_ptr<IPlugin> GetPluginByCode(std::uint32_t code);
    std::shared_ptr<IPluginExecuteStrategy> CreateExecuteStrategy(ExecuteStrategy strategy);
    std::shared_ptr<IPluginExecuteStrategy> enhanceStrategy_ = std::make_shared<EnhanceExecuteStrategy>();
    std::shared_ptr<IPluginExecuteStrategy> singleStrategy_ = std::make_shared<SingleExecuteStrategy>();
    std::shared_ptr<IPluginExecuteStrategy> replaceStrategy_ = std::make_shared<ReplaceExecuteStrategy>();
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_PLUGIN_MANAGER_H
