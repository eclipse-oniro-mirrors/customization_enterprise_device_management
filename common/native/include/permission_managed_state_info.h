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

#ifndef COMMON_NATIVE_INCLUDE_PERMISSION_MANAGED_INFO_H
#define COMMON_NATIVE_INCLUDE_PERMISSION_MANAGED_INFO_H
 
#include <string>

namespace OHOS {
namespace EDM {
enum class ManagedState: int32_t {
    DEFAULT = 1,
    GRANTED = 0,
    DENIED = -1
};

enum class PermissionFlag: uint32_t {
    PERMISSION_FIXED_BY_ADMIN_POLICY = 1 << 7,
    PERMISSION_ADMIN_POLICYS_CANCEL = 1 << 8
};

struct PermissionManagedStateInfo {
    std::string appId;
    std::string permissionName;
    int32_t accountId = 0;
    int32_t appIndex = 0;
    int32_t managedState = 0;
    std::vector<std::string> permissionNames;
};
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_PERMISSION_MANAGED_INFO_H
 