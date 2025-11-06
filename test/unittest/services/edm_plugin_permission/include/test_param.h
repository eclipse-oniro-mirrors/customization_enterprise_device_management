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

#ifndef EDM_UNIT_TEST_SERVICES_EDM_PLUGIN_PERMISSION_TEST_PARAM_H
#define EDM_UNIT_TEST_SERVICES_EDM_PLUGIN_PERMISSION_TEST_PARAM_H

#include <string>
#include <vector>

#include "admin_type.h"
#include "func_code.h"
#include "iplugin.h"

#include "add_os_account_plugin.h"
#include "allowed_app_distribution_types_plugin.h"
#include "allowed_bluetooth_devices_plugin.h"
#include "password_policy_plugin.h"
#include "set_browser_policies_plugin.h"

namespace OHOS {
namespace EDM {
namespace TEST {
class TestParam {
public:
    TestParam(uint32_t pluginCode, std::shared_ptr<IPlugin> plugin,
        AdminType adminType, bool isSystemHap, const std::string &permissionTag, const std::string &permissinName);
    TestParam(uint32_t pluginCode, std::shared_ptr<IPlugin> plugin, const std::string &permissionTag,
        const std::string &process, int32_t uid);
    uint32_t GetPluginCode();
    std::shared_ptr<IPlugin> GetPlugin();
    AdminType GetAdminType();
    bool IsSystemHap();
    std::string GetPermissionTag();
    std::string GetPermissionName();
    std::string GetProcess();
    int32_t GetUid();
private:
    uint32_t pluginCode_ = 0;
    std::shared_ptr<IPlugin> plugin_ = nullptr;
    AdminType adminType_ = AdminType::ENT;
    bool isSystemHap_ = false;
    std::string permissionTag_;
    std::string permissinName_;
    std::string process_;
    int32_t uid_ = 0;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_SERVICES_EDM_PLUGIN_PERMISSION_TEST_PARAM_H