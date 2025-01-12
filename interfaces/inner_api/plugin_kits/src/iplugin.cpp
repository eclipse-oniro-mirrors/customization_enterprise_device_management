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

#include "iplugin.h"
#include <string_ex.h>

namespace OHOS {
namespace EDM {
std::string IPlugin::GetPolicyName()
{
    return policyName_;
}

bool IPlugin::NeedSavePolicy()
{
    return needSave_;
}

bool IPlugin::IsGlobalPolicy()
{
    return isGlobal_;
}

std::vector<IPlugin::PolicyPermissionConfig> IPlugin::GetAllPermission()
{
    std::vector<IPlugin::PolicyPermissionConfig> allPermission;
    if (!permissionMap_.empty()) {
        for (auto &it : permissionMap_) {
            allPermission.push_back(it.second);
        }
    } else {
        allPermission.push_back(permissionConfig_);
    }
    return allPermission;
}

std::string IPlugin::GetPermission(FuncOperateType operaType, PermissionType permissionType, std::string permissionTag)
{
    if (!permissionMap_.empty() && permissionMap_.find(operaType) != permissionMap_.end()) {
        PolicyPermissionConfig config = permissionMap_[operaType];
        return CheckAndGetPermissionFromConfig(permissionType, permissionTag, config.tagPermissions,
            config.typePermissions);
    }
    return CheckAndGetPermissionFromConfig(permissionType, permissionTag, permissionConfig_.tagPermissions,
        permissionConfig_.typePermissions);
}

std::string IPlugin::CheckAndGetPermissionFromConfig(PermissionType permissionType, const std::string &permissionTag,
    std::map<std::string, std::map<PermissionType, std::string>> tagPermissions,
    std::map<PermissionType, std::string> typePermissions)
{
    if (!permissionTag.empty() && !tagPermissions.empty()) {
        auto it = tagPermissions.find(permissionTag);
        if (it == tagPermissions.end()) {
            return NONE_PERMISSION_MATCH;
        }
        
        const auto &typePermissionsForTag = it->second;
        if (typePermissionsForTag.size() == 1) {
            return typePermissionsForTag.begin()->second;
        }
        if (typePermissionsForTag.size() > 1) {
            auto typeIt = typePermissionsForTag.find(permissionType);
            if (typeIt != typePermissionsForTag.end()) {
                return typeIt->second;
            }
        }
    }
    if (!typePermissions.empty()) {
        if (typePermissions.size() == 1) {
            return typePermissions.begin()->second;
        }
        if (typePermissions.size() > 1) {
            auto typeIt = typePermissions.find(permissionType);
            if (typeIt != typePermissions.end()) {
                return typeIt->second;
            }
        }
    }
    return NONE_PERMISSION_MATCH;
}

IPlugin::ApiType IPlugin::GetApiType(FuncOperateType operaType)
{
    if (permissionConfig_.apiType == ApiType::UNKNOWN &&
        permissionMap_.find(operaType) != permissionMap_.end()) {
        return permissionMap_[operaType].apiType;
    }
    return permissionConfig_.apiType;
}

std::uint32_t IPlugin::GetCode()
{
    return policyCode_;
}

ErrCode IPlugin::GetOthersMergePolicyData(const std::string &adminName, std::string &othersMergePolicyData)
{
    return ERR_OK;
}

ErrCode IPlugin::WritePolicyToParcel(const std::string &policyJsonData, MessageParcel &reply)
{
    return reply.WriteString(policyJsonData) ? ERR_OK : ERR_EDM_OPERATE_PARCEL;
}

void IPlugin::SetExtensionPlugin(std::shared_ptr<IPlugin> extensionPlugin)
{
    extensionPlugin_ = extensionPlugin;
}

void IPlugin::ResetExtensionPlugin()
{
    if (extensionPlugin_ != nullptr) {
        extensionPlugin_.reset();
    }
}

std::shared_ptr<IPlugin> IPlugin::GetExtensionPlugin()
{
    return extensionPlugin_;
}

void IPlugin::SetExecuteStrategy(std::shared_ptr<IPluginExecuteStrategy> strategy)
{
    strategy_ = strategy;
}

std::shared_ptr<IPluginExecuteStrategy> IPlugin::GetExecuteStrategy()
{
    return strategy_;
}

void IPlugin::SetPluginType(IPlugin::PluginType type)
{
    type_ = type;
}

IPlugin::PluginType IPlugin::GetPluginType()
{
    return type_;
}

IPlugin::~IPlugin() {}
} // namespace EDM
} // namespace OHOS
