/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_QUERY_POLICY_POLICY_QUERY_CONFIG_H
#define SERVICES_EDM_INCLUDE_QUERY_POLICY_POLICY_QUERY_CONFIG_H

#include <cstdint>
#include <string>

#include "edm_errors.h"
#include "iplugin.h"

namespace OHOS {
namespace EDM {

enum class PolicyDataType {
    BOOL,
    ARRAY_STRING,
    INT,
    STRING,
    CUSTOM
};

enum class PermissionPattern : uint8_t {
    RESTRICTION,   // SuperAdmin返回ENTERPRISE，hasByod=true时BYOD返回PERSONAL，否则统一返回ENTERPRISE
    SPECIFIC,      // 所有管理员类型统一返回specificPermission指定的固定权限
    TAG            // SuperAdmin根据permissionTag选择tagPermission或specificPermission；BYOD选择byodPermission或回退到specificPermission
};

struct PermissionConfig {
    PermissionPattern pattern;          // 权限分发模式，决定GetPermission的分支逻辑
    bool hasByod;                       // RESTRICTION模式下是否有BYOD专属权限，true时BYOD返回PERSONAL权限
    const char* specificPermission;     // SPECIFIC/TAG模式下的默认权限(SuperAdmin/NormalAdmin使用)
                                        // TAG模式下BYOD无byodPermission时的回退权限
    const char* tagPermission;          // TAG模式下SuperAdmin+permissionTag非空时返回的权限
    const char* byodPermission;         // TAG模式下BYOD_DEVICE_ADMIN专属权限，为空时回退到specificPermission

    std::string GetPermission(IPlugin::PermissionType type, const std::string &permissionTag) const;

    static PermissionConfig RestrictionPermission(bool hasByod);
    static PermissionConfig RestrictionPermission();
    static PermissionConfig SpecificPermission(const char* permission);
    static PermissionConfig TagPermission(const char* tagPermission,
        const char* defaultPermission, const char* byodPermission = nullptr);
};

struct PolicyQueryConfig {
    const char* policyName;     // 策略名称常量，对应数据库中的策略键名（如POLICY_DISALLOWED_P2P）
    PolicyDataType dataType;   // 策略数据类型，决定GenericPolicyQuery的QueryPolicy分发分支
    PermissionConfig permissionConfig; // 权限配置，决定GetPermission的返回值
    bool isPolicySaved;        // 是否需要持久化到数据库，true时GetPolicy从数据库读取policyData
    IPlugin::ApiType apiType;  // API类型(PUBLIC/INNER/SYSTEM)，决定IPolicyQuery::GetPolicy的权限校验方式
    bool isFeatureEnabled;     // feature gate开关，false时CheckFeatureEnabled返回INTERFACE_UNSUPPORTED
};

struct PolicyQueryConfigEntry {
    uint32_t code;
    PolicyQueryConfig config;
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_QUERY_POLICY_POLICY_QUERY_CONFIG_H
