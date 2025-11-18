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

#include "test_param.h"

namespace OHOS {
namespace EDM {
namespace TEST {
TestParam::TestParam(uint32_t pluginCode, std::shared_ptr<IPlugin> plugin,
    AdminType adminType, bool isSystemHap, const std::string &permissionTag, const std::string &permissinName)
{
    pluginCode_ = pluginCode;
    plugin_ = plugin;
    adminType_ = adminType;
    isSystemHap_ = isSystemHap;
    permissionTag_ = permissionTag;
    permissinName_ = permissinName;
}

TestParam::TestParam(uint32_t pluginCode, std::shared_ptr<IPlugin> plugin, const std::string &permissionTag,
    const std::string &process, int32_t uid)
{
    pluginCode_ = pluginCode;
    plugin_ = plugin;
    permissionTag_ = permissionTag;
    process_ = process;
    uid_ = uid;
}

uint32_t TestParam::GetPluginCode()
{
    return pluginCode_;
}

std::shared_ptr<IPlugin> TestParam::GetPlugin()
{
    return plugin_;
}

AdminType TestParam::GetAdminType()
{
    return adminType_;
}

bool TestParam::IsSystemHap()
{
    return isSystemHap_;
}

std::string TestParam::GetPermissionTag()
{
    return permissionTag_;
}

std::string TestParam::GetPermissionName()
{
    return permissinName_;
}

std::string TestParam::GetProcess()
{
    return process_;
}

int32_t TestParam::GetUid()
{
    return uid_;
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS