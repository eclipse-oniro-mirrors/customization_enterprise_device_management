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

IPlugin::PolicyPermissionConfig IPlugin::GetAllPermission(FuncOperateType operaType)
{
    if (permissionConfig_.permissionType == PermissionType::UNKNOWN && permissionMap_.count(operaType) > 0) {
        return permissionMap_[operaType];
    }
    return permissionConfig_;
}

std::string IPlugin::GetPermission(FuncOperateType operaType, std::string permissionTag)
{
    if (permissionConfig_.permissionType == PermissionType::UNKNOWN && permissionMap_.count(operaType) > 0) {
        PolicyPermissionConfig config = permissionMap_[operaType];
        return CheckAndGetPermissionFromConfig(permissionTag, config.tagPermissions, config.permission);
    }
    return CheckAndGetPermissionFromConfig(permissionTag, permissionConfig_.tagPermissions,
        permissionConfig_.permission);
}

std::string IPlugin::CheckAndGetPermissionFromConfig(const std::string &permissionTag,
    std::map<std::string, std::string> tagPermissions, const std::string &commonPermission)
{
    if (permissionTag.empty()) {
        return tagPermissions.empty() ? commonPermission : NONE_PERMISSION_MATCH;
    } else {
        return (!tagPermissions.empty() && tagPermissions.count(permissionTag) > 0 ?
            tagPermissions[permissionTag] : NONE_PERMISSION_MATCH);
    }
}

IPlugin::PermissionType IPlugin::GetPermissionType(FuncOperateType operaType)
{
    if (permissionConfig_.permissionType == PermissionType::UNKNOWN && permissionMap_.count(operaType) > 0) {
        return permissionMap_[operaType].permissionType;
    }
    return permissionConfig_.permissionType;
}

IPlugin::ApiType IPlugin::GetApiType(FuncOperateType operaType)
{
    if (permissionConfig_.apiType == ApiType::UNKNOWN && permissionMap_.count(operaType) > 0) {
        return permissionMap_[operaType].apiType;
    }
    return permissionConfig_.apiType;
}

std::uint32_t IPlugin::GetCode()
{
    return policyCode_;
}

ErrCode IPlugin::MergePolicyData(const std::string &adminName, std::string &mergeJsonData)
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
