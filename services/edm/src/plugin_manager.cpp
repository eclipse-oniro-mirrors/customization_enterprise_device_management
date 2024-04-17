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

#include "plugin_manager.h"

#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <string_ex.h>
#include <unistd.h>

#include "edm_log.h"
#include "func_code_utils.h"
#include "permission_manager.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<PluginManager> PluginManager::instance_;
std::mutex PluginManager::mutexLock_;

PluginManager::PluginManager()
{
    EDMLOGD("PluginManager::PluginManager.");
}

PluginManager::~PluginManager()
{
    EDMLOGD("PluginManager::~PluginManager.");
    for (auto entry : pluginsCode_) {
        entry.second.reset();
        entry.second = nullptr;
    }
    pluginsCode_.clear();
    for (auto handle : pluginHandles_) {
        dlclose(handle);
    }
    pluginHandles_.clear();
}

std::shared_ptr<PluginManager> PluginManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(mutexLock_);
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) PluginManager());
        }
    }

    IPluginManager::pluginManagerInstance_ = instance_.get();
    return instance_;
}

std::shared_ptr<IPlugin> PluginManager::GetPluginByFuncCode(std::uint32_t funcCode)
{
    FuncCodeUtils::PrintFuncCode(funcCode);
    FuncFlag flag = FuncCodeUtils::GetSystemFlag(funcCode);
    if (flag == FuncFlag::POLICY_FLAG) {
        std::uint32_t code = FuncCodeUtils::GetPolicyCode(funcCode);
        EDMLOGD("PluginManager::code %{public}u", code);
        auto it = pluginsCode_.find(code);
        if (it != pluginsCode_.end()) {
            return it->second;
        }
    }
    EDMLOGD("GetPluginByFuncCode::return nullptr");
    return nullptr;
}

std::shared_ptr<IPlugin> PluginManager::GetPluginByPolicyName(const std::string &policyName)
{
    auto it = pluginsName_.find(policyName);
    if (it != pluginsName_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<IPlugin> PluginManager::GetPluginByCode(std::uint32_t code)
{
    EDMLOGD("PluginManager::code %{public}u", code);
    auto it = pluginsCode_.find(code);
    if (it != pluginsCode_.end()) {
        return it->second;
    }
    EDMLOGD("GetPluginByCode::return nullptr");
    return nullptr;
}

std::shared_ptr<IPluginExecuteStrategy> PluginManager::CreateExecuteStrategy(ExecuteStrategy strategy)
{
    if (strategy == ExecuteStrategy::ENHANCE) {
        return enhanceStrategy_;
    }
    return singleStrategy_;
}

bool PluginManager::AddPlugin(std::shared_ptr<IPlugin> plugin)
{
    if (plugin == nullptr) {
        return false;
    }
    EDMLOGD("AddPlugin %{public}d", plugin->GetCode());
    IPlugin::PolicyPermissionConfig setConfig = plugin->GetAllPermission(FuncOperateType::SET);
    IPlugin::PolicyPermissionConfig getConfig = plugin->GetAllPermission(FuncOperateType::GET);
    IPlugin::PermissionType setType = plugin->GetPermissionType(FuncOperateType::SET);
    IPlugin::PermissionType getType = plugin->GetPermissionType(FuncOperateType::GET);
    ErrCode result = PermissionManager::GetInstance()->AddPermission(setConfig.permission, setType);
    if (result == ERR_OK && getConfig.permission != setConfig.permission) {
        result = PermissionManager::GetInstance()->AddPermission(getConfig.permission, getType);
    }
    if (result == ERR_OK) {
        for (auto &item : setConfig.tagPermissions) {
            if (PermissionManager::GetInstance()->AddPermission(item.second, setType) != ERR_OK) {
                return false;
            }
        }
        for (auto &item : getConfig.tagPermissions) {
            if (PermissionManager::GetInstance()->AddPermission(item.second, getType) != ERR_OK) {
                return false;
            }
        }
        pluginsCode_.insert(std::make_pair(plugin->GetCode(), plugin));
        pluginsName_.insert(std::make_pair(plugin->GetPolicyName(), plugin));
        if (extensionPluginMap_.count(plugin->GetCode()) > 0) {
            EDMLOGD("PluginManager::AddPlugin %{public}d add extension plugin %{public}d", plugin->GetCode(),
                extensionPluginMap_[plugin->GetCode()]);
            plugin->SetExtensionPlugin(GetPluginByCode(extensionPluginMap_[plugin->GetCode()]));
        }
        if (executeStrategyMap_.count(plugin->GetCode()) > 0) {
            plugin->SetExecuteStrategy(CreateExecuteStrategy(executeStrategyMap_[plugin->GetCode()]));
        } else {
            plugin->SetExecuteStrategy(CreateExecuteStrategy(ExecuteStrategy::SINGLE));
        }
        return true;
    }
    return false;
}

bool PluginManager::AddExtensionPlugin(std::shared_ptr<IPlugin> extensionPlugin, uint32_t basicPluginCode,
    ExecuteStrategy strategy)
{
    if (AddPlugin(extensionPlugin)) {
        auto basicPlugin = GetPluginByCode(basicPluginCode);
        if (basicPlugin != nullptr) {
            EDMLOGD("PluginManager::AddExtensionPlugin %{public}d add extension plugin %{public}d", basicPluginCode,
                extensionPlugin->GetCode());
            basicPlugin->SetExtensionPlugin(extensionPlugin);
            basicPlugin->SetExecuteStrategy(CreateExecuteStrategy(strategy));
        }
        extensionPlugin->SetPluginType(IPlugin::PluginType::EXTENSION);
        extensionPluginMap_.insert(std::make_pair(basicPluginCode, extensionPlugin->GetCode()));
        executeStrategyMap_.insert(std::make_pair(basicPluginCode, strategy));
        return true;
    }
    return false;
}

void PluginManager::Init()
{
    LoadPlugin();
}

void PluginManager::LoadPlugin()
{
#ifdef _ARM64_
    std::string pluginDir = "/system/lib64/edm_plugin/";
#else
    std::string pluginDir = "/system/lib/edm_plugin/";
#endif
    DIR *dir = opendir(pluginDir.c_str());
    if (dir == nullptr) {
        EDMLOGE("PluginManager::LoadPlugin open edm_plugin dir fail.");
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_REG && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            LoadPlugin(pluginDir + entry->d_name);
        }
    }
    closedir(dir);
}

void PluginManager::LoadPlugin(const std::string &pluginPath)
{
    void *handle = dlopen(pluginPath.c_str(), RTLD_LAZY);
    if (!handle) {
        EDMLOGE("PluginManager::open plugin so fail. %{public}s.", dlerror());
        return;
    }
    char *szError = dlerror();
    if (szError != nullptr) {
        EDMLOGW("PluginManager::loading plugin fail. %{public}s.", szError);
    }
    pluginHandles_.push_back(handle);
}

void PluginManager::DumpPlugin()
{
    for (auto it = pluginsCode_.begin(); it != pluginsCode_.end(); it++) {
        std::string setTagPermissions;
        std::string getTagPermissions;
        IPlugin::PolicyPermissionConfig setConfig = it->second->GetAllPermission(FuncOperateType::SET);
        IPlugin::PolicyPermissionConfig getConfig = it->second->GetAllPermission(FuncOperateType::GET);
        for (auto &item : setConfig.tagPermissions) {
            setTagPermissions.append(item.second);
        }
        for (auto &item : getConfig.tagPermissions) {
            getTagPermissions.append(item.second);
        }
        EDMLOGD("PluginManager::Dump plugins_code.code:%{public}u,name:%{public}s,get permission:%{public}s, "
            "set permission:%{public}s,get tagPermissions:%{public}s,set tagPermissions:%{public}s",
            it->first, it->second->GetPolicyName().c_str(),
            it->second->GetPermission(FuncOperateType::GET).c_str(),
            it->second->GetPermission(FuncOperateType::SET).c_str(),
            getTagPermissions.c_str(), setTagPermissions.c_str());
    }
    for (auto it = pluginsName_.begin(); it != pluginsName_.end(); it++) {
        std::string setTagPermissions;
        std::string getTagPermissions;
        IPlugin::PolicyPermissionConfig setConfig = it->second->GetAllPermission(FuncOperateType::SET);
        IPlugin::PolicyPermissionConfig getConfig = it->second->GetAllPermission(FuncOperateType::GET);
        for (auto &item : setConfig.tagPermissions) {
            setTagPermissions.append(item.second);
        }
        for (auto &item : getConfig.tagPermissions) {
            getTagPermissions.append(item.second);
        }
        EDMLOGD("PluginManager::Dump plugins_name.name:%{public}s,code:%{public}u,get permission type:%{public}s, "
            "set permission type:%{public}s,get tagPermissions:%{public}s,set tagPermissions:%{public}s",
            it->first.c_str(), it->second->GetCode(),
            it->second->GetPermission(FuncOperateType::GET).c_str(),
            it->second->GetPermission(FuncOperateType::SET).c_str(),
            getTagPermissions.c_str(), setTagPermissions.c_str());
    }
}
} // namespace EDM
} // namespace OHOS
