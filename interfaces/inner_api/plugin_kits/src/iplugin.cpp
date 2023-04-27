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

std::string IPlugin::GetPermission(FuncOperateType operaType)
{
    if (permission_.empty() && permissionMap_.count(operaType) > 0) {
        return permissionMap_[operaType].first;
    }
    return permission_;
}

IPlugin::PermissionType IPlugin::GetPermissionType(FuncOperateType operaType)
{
    if (permissionType_ == PermissionType::UNKNOWN && permissionMap_.count(operaType) > 0) {
        return permissionMap_[operaType].second;
    }
    return permissionType_;
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

IPlugin::~IPlugin() {}
} // namespace EDM
} // namespace OHOS
