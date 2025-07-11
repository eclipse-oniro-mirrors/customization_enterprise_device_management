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

#include <dirent.h>
#include <dlfcn.h>
#include <string_ex.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "permission_manager.h"

namespace OHOS {
namespace EDM {
#if defined(_ARM64_) || defined(_X86_64_)
const char* const PLUGIN_DIR = "/system/lib64/edm_plugin/";
#else
const char* const PLUGIN_DIR = "/system/lib/edm_plugin/";
#endif

std::shared_ptr<PluginManager> PluginManager::instance_;
std::shared_timed_mutex PluginManager::mutexLock_;
constexpr int32_t TIMER_TIMEOUT = 180000; // 3 * 60 * 1000;
constexpr int32_t MUTEX_TIMEOUT = 10;;

std::vector<uint32_t> PluginManager::deviceCoreSoCodes_ = {
    EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT, EdmInterfaceCode::ALLOWED_INSTALL_BUNDLES,
    EdmInterfaceCode::DISALLOW_MODIFY_DATETIME, EdmInterfaceCode::DISALLOWED_INSTALL_BUNDLES,
    EdmInterfaceCode::SCREEN_OFF_TIME, EdmInterfaceCode::DISALLOWED_UNINSTALL_BUNDLES,
    EdmInterfaceCode::UNINSTALL, EdmInterfaceCode::DISABLED_PRINTER,
    EdmInterfaceCode::DISABLED_HDC, EdmInterfaceCode::INSTALL,
    EdmInterfaceCode::POWER_POLICY, EdmInterfaceCode::NTP_SERVER,
    EdmInterfaceCode::LOCK_SCREEN, EdmInterfaceCode::SHUTDOWN,
    EdmInterfaceCode::REBOOT, EdmInterfaceCode::DISALLOW_ADD_OS_ACCOUNT_BY_USER,
    EdmInterfaceCode::ADD_OS_ACCOUNT, EdmInterfaceCode::GET_BLUETOOTH_INFO,
    EdmInterfaceCode::DISABLE_MICROPHONE, EdmInterfaceCode::DISABLE_BLUETOOTH,
    EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES, EdmInterfaceCode::INACTIVE_USER_FREEZE,
    EdmInterfaceCode::SNAPSHOT_SKIP, EdmInterfaceCode::WATERMARK_IMAGE,
    EdmInterfaceCode::DISABLE_CAMERA, EdmInterfaceCode::DOMAIN_ACCOUNT_POLICY,
    EdmInterfaceCode::DISABLE_MAINTENANCE_MODE, EdmInterfaceCode::SWITCH_BLUETOOTH,
    EdmInterfaceCode::GET_BUNDLE_INFO_LIST, EdmInterfaceCode::DISABLE_BACKUP_AND_RESTORE,
    EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES, EdmInterfaceCode::DISABLE_REMOTE_DESK,
    EdmInterfaceCode::DISABLE_REMOTE_DIAGNOSIS, EdmInterfaceCode::DISABLE_USER_MTP_CLIENT,
    EdmInterfaceCode::DISALLOW_POWER_LONG_PRESS, EdmInterfaceCode::ALLOWED_KIOSK_APPS,
    EdmInterfaceCode::SET_KIOSK_FEATURE, EdmInterfaceCode::DISABLE_SET_BIOMETRICS_AND_SCREENLOCK,
    EdmInterfaceCode::DISABLE_SET_DEVICE_NAME, EdmInterfaceCode::SET_AUTO_UNLOCK_AFTER_REBOOT,
    EdmInterfaceCode::DISABLE_MTP_CLIENT, EdmInterfaceCode::DISABLE_MTP_SERVER,
    EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION, EdmInterfaceCode::DISALLOWED_EXPORT_RECOVERY_KEY,
    EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE, EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED,
    EdmInterfaceCode::DISALLOWED_NEARLINK_PROTOCOLS, EdmInterfaceCode::DISALLOWED_BLUETOOTH_PROTOCOLS,
    EdmInterfaceCode::DISALLOWED_SUDO, EdmInterfaceCode::DISABLE_PRIVATE_SPACE,
    EdmInterfaceCode::DISABLED_PRINT,
};

std::vector<uint32_t> PluginManager::communicationSoCodes_ = {
    EdmInterfaceCode::IS_WIFI_ACTIVE, EdmInterfaceCode::GET_NETWORK_INTERFACES,
    EdmInterfaceCode::GET_IP_ADDRESS, EdmInterfaceCode::GET_MAC,
    EdmInterfaceCode::SET_WIFI_PROFILE, EdmInterfaceCode::DISABLED_NETWORK_INTERFACE,
    EdmInterfaceCode::IPTABLES_RULE, EdmInterfaceCode::SET_BROWSER_POLICIES,
    EdmInterfaceCode::GLOBAL_PROXY, EdmInterfaceCode::USB_READ_ONLY,
    EdmInterfaceCode::FIREWALL_RULE, EdmInterfaceCode::DOMAIN_FILTER_RULE,
    EdmInterfaceCode::DISABLE_USB, EdmInterfaceCode::ALLOWED_USB_DEVICES,
    EdmInterfaceCode::DISABLE_WIFI, EdmInterfaceCode::DISALLOWED_TETHERING,
    EdmInterfaceCode::DISALLOWED_USB_DEVICES, EdmInterfaceCode::MANAGED_BROWSER_POLICY,
    EdmInterfaceCode::ALLOWED_WIFI_LIST, EdmInterfaceCode::DISALLOWED_WIFI_LIST,
    EdmInterfaceCode::DISALLOWED_SMS, EdmInterfaceCode::DISALLOWED_MMS,
    EdmInterfaceCode::SWITCH_WIFI, EdmInterfaceCode::DISALLOW_MODIFY_APN,
    EdmInterfaceCode::TURNONOFF_MOBILE_DATA, EdmInterfaceCode::SET_APN_INFO,
    EdmInterfaceCode::DISALLOWED_SIM, EdmInterfaceCode::DISALLOWED_MOBILE_DATA,
    EdmInterfaceCode::DISABLE_SAMBA_CLIENT, EdmInterfaceCode::DISABLE_SAMBA_SERVER,
    EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP,
    EdmInterfaceCode::DISALLOWED_AIRPLANE_MODE, EdmInterfaceCode::TELEPHONY_CALL_POLICY,
    EdmInterfaceCode::DISALLOWED_TELEPHONY_CALL, EdmInterfaceCode::DISALLOW_VPN
};

std::vector<uint32_t> PluginManager::sysServiceSoCodes_ = {
    EdmInterfaceCode::SET_DATETIME, EdmInterfaceCode::RESET_FACTORY,
    EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES, EdmInterfaceCode::INSTALL_CERTIFICATE,
    EdmInterfaceCode::LOCATION_POLICY, EdmInterfaceCode::MANAGE_AUTO_START_APPS,
    EdmInterfaceCode::FINGERPRINT_AUTH, EdmInterfaceCode::PASSWORD_POLICY,
    EdmInterfaceCode::CLIPBOARD_POLICY, EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS,
    EdmInterfaceCode::CLEAR_UP_APPLICATION_DATA, EdmInterfaceCode::DISALLOWED_NOTIFICATION,
    EdmInterfaceCode::PERMISSION_MANAGED_STATE
};

std::vector<uint32_t> PluginManager::needExtraSoCodes_ = {
    EdmInterfaceCode::GET_DEVICE_SERIAL, EdmInterfaceCode::GET_DEVICE_NAME,
    EdmInterfaceCode::GET_DEVICE_INFO, EdmInterfaceCode::OPERATE_DEVICE,
    EdmInterfaceCode::SET_OTA_UPDATE_POLICY, EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES,
    EdmInterfaceCode::GET_ADMINPROVISION_INFO, EdmInterfaceCode::SET_WALL_PAPER
};

PluginManager::PluginManager()
{
    EDMLOGD("PluginManager::PluginManager.");
}

PluginManager::~PluginManager()
{
    EDMLOGD("PluginManager::~PluginManager.");
#ifndef EDM_FUZZ_TEST
    NotifyUnloadAllPlugin();
#endif
}

std::shared_ptr<PluginManager> PluginManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::unique_lock<std::shared_timed_mutex> autoLock(mutexLock_);
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
    EDMLOGI("GetPluginByCode::return nullptr");
    return nullptr;
}

std::shared_ptr<IPluginExecuteStrategy> PluginManager::CreateExecuteStrategy(ExecuteStrategy strategy)
{
    if (strategy == ExecuteStrategy::ENHANCE) {
        return enhanceStrategy_;
    }
    if (strategy == ExecuteStrategy::REPLACE) {
        return replaceStrategy_;
    }
    return singleStrategy_;
}

bool PluginManager::AddPlugin(std::shared_ptr<IPlugin> plugin)
{
    if (plugin == nullptr) {
        return false;
    }
    EDMLOGD("AddPlugin %{public}d", plugin->GetCode());
    return AddPluginInner(plugin);
}

bool PluginManager::AddPluginInner(std::shared_ptr<IPlugin> plugin)
{
    if (plugin == nullptr) {
        return false;
    }
    EDMLOGD("AddPlugin %{public}d", plugin->GetCode());
    std::vector<IPlugin::PolicyPermissionConfig> configs = plugin->GetAllPermission();
    if (configs.empty()) {
        return false;
    }
    for (auto &config : configs) {
        for (auto &typePermission : config.typePermissions) {
            PermissionManager::GetInstance()->AddPermission(typePermission.second,
                typePermission.first, plugin->GetCode());
        }
        for (auto &tagPermission : config.tagPermissions) {
            for (auto &typePermission : tagPermission.second) {
                PermissionManager::GetInstance()->AddPermission(typePermission.second,
                    typePermission.first, plugin->GetCode());
            }
        }
    }
    pluginsCode_.insert(std::make_pair(plugin->GetCode(), plugin));
    pluginsName_.insert(std::make_pair(plugin->GetPolicyName(), plugin));
    if (extensionPluginMap_.find(plugin->GetCode()) != extensionPluginMap_.end()) {
        EDMLOGD("PluginManager::AddPlugin %{public}d add extension plugin %{public}d", plugin->GetCode(),
            extensionPluginMap_[plugin->GetCode()]);
        plugin->SetExtensionPlugin(GetPluginByCode(extensionPluginMap_[plugin->GetCode()]));
    }
    if (executeStrategyMap_.find(plugin->GetCode()) != executeStrategyMap_.end()) {
        plugin->SetExecuteStrategy(CreateExecuteStrategy(executeStrategyMap_[plugin->GetCode()]));
    } else {
        plugin->SetExecuteStrategy(CreateExecuteStrategy(ExecuteStrategy::SINGLE));
    }
    return true;
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
        extensionPlugin->SetBasicPluginCode(basicPluginCode);
        extensionPlugin->SetPluginType(IPlugin::PluginType::EXTENSION);
        extensionPluginMap_.insert(std::make_pair(basicPluginCode, extensionPlugin->GetCode()));
        executeStrategyMap_.insert(std::make_pair(basicPluginCode, strategy));
        return true;
    }
    return false;
}

void PluginManager::LoadAllPlugin()
{
    LoadPlugin(SONAME::DEVICE_CORE_PLUGIN_SO);
    LoadPlugin(SONAME::COMMUNICATION_PLUGIN_SO);
    LoadPlugin(SONAME::SYS_SERVICE_PLUGIN_SO);
    LoadPlugin(SONAME::NEED_EXTRA_PLUGIN_SO);
    LoadExtraPlugin();
}

void PluginManager::LoadExtraPlugin()
{
    EDMLOGI("PluginManager::LoadExtraPlugin start.");
    DIR *dir = opendir(PLUGIN_DIR);
    if (dir == nullptr) {
        EDMLOGE("PluginManager::LoadPlugin open edm_plugin dir fail.");
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_REG && IsExtraPlugin(entry->d_name)) {
            LoadPlugin(entry->d_name);
        }
    }
    closedir(dir);
}

bool PluginManager::IsExtraPlugin(const std::string &soName)
{
    return soName != SONAME::DEVICE_CORE_PLUGIN_SO
        && soName != SONAME::COMMUNICATION_PLUGIN_SO
        && soName != SONAME::SYS_SERVICE_PLUGIN_SO
        && soName != SONAME::NEED_EXTRA_PLUGIN_SO
        && soName != SONAME::OLD_EDM_PLUGIN_SO;
}

ErrCode PluginManager::LoadPluginByFuncCode(uint32_t funcCode)
{
    std::uint32_t code = FuncCodeUtils::GetPolicyCode(funcCode);
    return LoadPluginByCode(code);
}

ErrCode PluginManager::LoadPluginByCode(uint32_t code)
{
    if (code > EdmInterfaceCode::POLICY_CODE_END) {
        LoadExtraPlugin();
        return ERR_OK;
    }
    std::string soName;
    if (!GetSoNameByCode(code, soName)) {
        EDMLOGE("PluginManager::LoadPluginByCode soname not found");
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (soName == SONAME::NEED_EXTRA_PLUGIN_SO) {
        LoadExtraPlugin();
    }
    LoadPlugin(soName);
    return ERR_OK;
}

void PluginManager::LoadPlugin(const std::string &soName)
{
    if (soName.empty()) {
        EDMLOGE("PluginManager::LoadPlugin soName empty");
        return;
    }
    std::unique_lock<std::shared_timed_mutex> lock(mutexLock_, std::chrono::seconds(MUTEX_TIMEOUT));
    if (!lock) {
        EDMLOGE("PluginManager::UnloadPlugin mutex timeout.");
        return;
    }
    EDMLOGI("PluginManager::LoadPlugin soName %{public}s", soName.c_str());
    auto soLoadIter = soLoadStateMap_.find(soName);
    if (soLoadIter == soLoadStateMap_.end()) {
        soLoadStateMap_[soName] = std::make_shared<SoLoadState>();
    }
    std::shared_ptr<SoLoadState> loadStatePtr = soLoadStateMap_[soName];
    loadStatePtr->lastCallTime = std::chrono::system_clock::now();
    if (loadStatePtr->pluginHasInit) {
        std::unique_lock<std::mutex> lock(loadStatePtr->waitMutex);
        loadStatePtr->notifySignal = true;
        loadStatePtr->waitSignal.notify_one();
    } else {
        EDMLOGI("PluginManager::DlopenPlugin soName %{public}s", soName.c_str());
        DlopenPlugin(PLUGIN_DIR + soName, loadStatePtr);
        loadStatePtr->pluginHasInit = true;
        std::thread timerThread([=]() {
            this->UnloadPluginTask(soName, loadStatePtr);
        });
        timerThread.detach();
    }
}

void PluginManager::UnloadPluginTask(const std::string &soName, std::shared_ptr<SoLoadState> loadStatePtr)
{
    while (loadStatePtr->pluginHasInit) {
        {
            std::unique_lock<std::mutex> lock(loadStatePtr->waitMutex);
            loadStatePtr->notifySignal = false;
            loadStatePtr->waitSignal.wait_for(lock, std::chrono::milliseconds(TIMER_TIMEOUT), [=] {
                return loadStatePtr->notifySignal;
            });
        }
        std::unique_lock<std::shared_timed_mutex> lock(mutexLock_);
        auto now = std::chrono::system_clock::now();
        auto diffTime = std::chrono::duration_cast<std::chrono::milliseconds>(now - loadStatePtr->lastCallTime).count();
        if (diffTime >= std::chrono::milliseconds(TIMER_TIMEOUT).count()) {
            UnloadPlugin(soName);
            loadStatePtr->pluginHasInit = false;
        }
    }
}

void PluginManager::DlopenPlugin(const std::string &pluginPath, std::shared_ptr<SoLoadState> loadStatePtr)
{
    void *handle = dlopen(pluginPath.c_str(), RTLD_LAZY);
    if (!handle) {
        EDMLOGE("PluginManager::open plugin so fail. %{public}s.", dlerror());
        return;
    }
    loadStatePtr->pluginHandles = handle;
}

bool PluginManager::GetSoNameByCode(std::uint32_t code, std::string &soName)
{
    auto deviceCoreIter = std::find(deviceCoreSoCodes_.begin(), deviceCoreSoCodes_.end(), code);
    if (deviceCoreIter != deviceCoreSoCodes_.end()) {
        soName = SONAME::DEVICE_CORE_PLUGIN_SO;
        return true;
    }
    auto communicationIter = std::find(communicationSoCodes_.begin(), communicationSoCodes_.end(), code);
    if (communicationIter != communicationSoCodes_.end()) {
        soName = SONAME::COMMUNICATION_PLUGIN_SO;
        return true;
    }
    auto sysServiceIter = std::find(sysServiceSoCodes_.begin(), sysServiceSoCodes_.end(), code);
    if (sysServiceIter != sysServiceSoCodes_.end()) {
        soName = SONAME::SYS_SERVICE_PLUGIN_SO;
        return true;
    }
    auto needExtraIter = std::find(needExtraSoCodes_.begin(), needExtraSoCodes_.end(), code);
    if (needExtraIter != needExtraSoCodes_.end()) {
        soName = SONAME::NEED_EXTRA_PLUGIN_SO;
        return true;
    }
    return false;
}

void PluginManager::UnloadPlugin(const std::string &soName)
{
    EDMLOGI("PluginManager::UnloadPlugin soName: %{public}s.", soName.c_str());
    std::vector<uint32_t>* targetVec = nullptr;
    std::vector<uint32_t> extraPluginCodeList;
    if (soName == SONAME::DEVICE_CORE_PLUGIN_SO) {
        targetVec = &deviceCoreSoCodes_;
    } else if (soName == SONAME::COMMUNICATION_PLUGIN_SO) {
        targetVec = &communicationSoCodes_;
    } else if (soName == SONAME::SYS_SERVICE_PLUGIN_SO) {
        targetVec = &sysServiceSoCodes_;
    } else if (soName == SONAME::NEED_EXTRA_PLUGIN_SO) {
        targetVec = &needExtraSoCodes_;
    } else {
        targetVec = &extraPluginCodeList;
        GetExtraPluginCodeList(targetVec);
        extensionPluginMap_.clear();
        executeStrategyMap_.clear();
    }
    for (const auto& code : *targetVec) {
        RemovePlugin(GetPluginByCode(code));
    }
    if (soLoadStateMap_.find(soName) == soLoadStateMap_.end()) {
        EDMLOGE("PluginManager::UnloadPlugin this so %{public}s not find", soName.c_str());
        return;
    }
    std::shared_ptr<SoLoadState> loadStatePtr = soLoadStateMap_[soName];
    if (loadStatePtr == nullptr || loadStatePtr->pluginHandles == nullptr) {
        EDMLOGE("PluginManager::UnloadPlugin %{public}s handle nullptr", soName.c_str());
        return;
    }
    int result = dlclose(loadStatePtr->pluginHandles);
    if (result != 0) {
        EDMLOGE("PluginManager::UnloadPlugin %{public}s close lib failed: %{public}s.", soName.c_str(), dlerror());
    } else {
        EDMLOGI("PluginManager::UnloadPlugin %{public}s close lib success", soName.c_str());
    }
    soLoadStateMap_.erase(soName);
}

void PluginManager::GetExtraPluginCodeList(std::vector<uint32_t>* targetVec)
{
    for (const auto& it : pluginsCode_) {
        if (it.first > EdmInterfaceCode::POLICY_CODE_END) {
            targetVec->push_back(it.first);
        }
    }
    for (const auto& it : extensionPluginMap_) {
        targetVec->push_back(it.second);
    }
}

void PluginManager::RemovePlugin(std::shared_ptr<IPlugin> plugin)
{
    if (plugin == nullptr) {
        return;
    }
    extensionPluginMap_.erase(plugin->GetCode());
    plugin->ResetExtensionPlugin();
    std::vector<IPlugin::PolicyPermissionConfig> configs = plugin->GetAllPermission();
    if (configs.empty()) {
        return;
    }
    pluginsCode_.erase(plugin->GetCode());
    pluginsName_.erase(plugin->GetPolicyName());
    auto basicPlugin = GetPluginByCode(plugin->GetBasicPluginCode());
    if (basicPlugin != nullptr) {
        basicPlugin->ResetExtensionPlugin();
    }
}

void PluginManager::NotifyUnloadAllPlugin()
{
    std::unique_lock<std::shared_timed_mutex> lock(mutexLock_);
    for (const auto& it : soLoadStateMap_) {
        auto state = it.second;
        if (state->pluginHasInit) {
            state->pluginHasInit = false;
            std::unique_lock<std::mutex> lock(state->waitMutex);
            state->notifySignal = true;
            state->lastCallTime = std::chrono::system_clock::time_point(std::chrono::milliseconds(0));
            state->waitSignal.notify_one();
        }
    }
}

void PluginManager::DumpPluginConfig(IPlugin::PolicyPermissionConfig config)
{
    std::string permissionStr;
    permissionStr.append("Type Permissions:");
    for (const auto &typePermission : config.typePermissions) {
        permissionStr.append("PermissionType: ");
        if (typePermission.first == IPlugin::PermissionType::NORMAL_DEVICE_ADMIN) {
            permissionStr.append("NORMAL_DEVICE_ADMIN:");
        }
        if (typePermission.first == IPlugin::PermissionType::SUPER_DEVICE_ADMIN) {
            permissionStr.append("SUPER_DEVICE_ADMIN:");
        }
        if (typePermission.first == IPlugin::PermissionType::BYOD_DEVICE_ADMIN) {
            permissionStr.append("BYOD_DEVICE_ADMIN:");
        }
        permissionStr.append(typePermission.second);
    }
    permissionStr.append("Tag Permissions:");
    for (const auto &tagPermission : config.tagPermissions) {
        permissionStr.append("ApiTag: ");
        permissionStr.append(tagPermission.first);
        for (const auto &tag : tagPermission.second) {
            if (tag.first == IPlugin::PermissionType::NORMAL_DEVICE_ADMIN) {
                permissionStr.append("NORMAL_DEVICE_ADMIN:");
            }
            if (tag.first == IPlugin::PermissionType::SUPER_DEVICE_ADMIN) {
                permissionStr.append("SUPER_DEVICE_ADMIN:");
            }
            if (tag.first == IPlugin::PermissionType::BYOD_DEVICE_ADMIN) {
                permissionStr.append("BYOD_DEVICE_ADMIN:");
            }
            permissionStr.append(tag.second);
        }
    }
    EDMLOGD("Config permission:%{public}s", permissionStr.c_str());
}

void PluginManager::DumpPlugin()
{
    DumpPluginInner(pluginsCode_, pluginsName_);
}

void PluginManager::DumpPluginInner(std::map<std::uint32_t, std::shared_ptr<IPlugin>> pluginsCode,
    std::map<std::string, std::shared_ptr<IPlugin>> pluginsName)
{
    for (auto it = pluginsCode.begin(); it != pluginsCode.end(); it++) {
        std::vector<IPlugin::PolicyPermissionConfig> configs = it->second->GetAllPermission();
        EDMLOGD("PluginManager::Dump plugins_code.code:%{public}u,name:%{public}s", it->first,
            it->second->GetPolicyName().c_str());
        for (auto &config : configs) {
            DumpPluginConfig(config);
        }
    }
    for (auto it = pluginsName.begin(); it != pluginsName.end(); it++) {
        std::vector<IPlugin::PolicyPermissionConfig> configs = it->second->GetAllPermission();
        EDMLOGD("PluginManager::Dump plugins_name.name:%{public}s,code:%{public}u", it->first.c_str(),
            it->second->GetCode());
        for (auto &config : configs) {
            DumpPluginConfig(config);
        }
    }
}
} // namespace EDM
} // namespace OHOS
