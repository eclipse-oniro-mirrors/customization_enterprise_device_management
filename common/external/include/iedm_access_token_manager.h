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

#ifndef COMMON_EXTERNAL_INCLUDE_IEDM_ACCESS_TOKEN_MANAGER_H
#define COMMON_EXTERNAL_INCLUDE_IEDM_ACCESS_TOKEN_MANAGER_H

#include <string>

namespace OHOS {
namespace EDM {
class IEdmAccessTokenManager {
public:
    virtual ~IEdmAccessTokenManager() = default;
    virtual bool IsDebug() = 0;
    virtual bool IsSystemAppOrNative() = 0;
    virtual bool VerifyCallingPermission(const std::string &permissionName) = 0;
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_EXTERNAL_INCLUDE_IEDM_ACCESS_TOKEN_MANAGER_H