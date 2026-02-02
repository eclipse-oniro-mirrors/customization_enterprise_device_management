/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_UTILS_UPDATE_POLICY_INFO_H
#define INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_UTILS_UPDATE_POLICY_INFO_H

#include <string>
#include <vector>

#include "edm_constants.h"

namespace OHOS {
namespace EDM {
enum class UpdatePolicyType {
    DEFAULT = 0,
    PROHIBIT,
    UPDATE_TO_SPECIFIC_VERSION,
    WINDOWS,
    POSTPONE
};

enum class PackageType {
    UNKNOWN = 0,
    FIRMWARE = 1
};

enum class OtaPolicyType {
    DEFAULT = -1, // 默认值，不处理
    ENABLE_OTA = 0, // 允许OTA
    DISABLE_OTA = 1 // 不允许OTA
};

struct UpdateTime {
    int64_t latestUpdateTime = 0;
    int64_t delayUpdateTime = 0;
    int64_t installWindowStart = 0;
    int64_t installWindowEnd = 0;
};

struct UpdatePolicy {
    UpdatePolicyType type = UpdatePolicyType::DEFAULT;
    std::string version;
    UpdateTime installTime;
    OtaPolicyType otaPolicyType = OtaPolicyType::DEFAULT;
};

struct Package {
    std::string path;
    PackageType type = PackageType::UNKNOWN;
    int32_t fd = -1;
};

struct NotifyDescription {
    std::string installTips;
    std::string installTipsDetail;
};

struct PackageDescription {
    NotifyDescription notify;
};

struct UpgradePackageInfo {
    std::string version;
    std::vector<Package> packages;
    PackageDescription description;
    char authInfo[EdmConstants::AUTH_INFO_MAX_SIZE] = {0};
    uint32_t authInfoSize = 0;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_UTILS_UPDATE_POLICY_INFO_H
