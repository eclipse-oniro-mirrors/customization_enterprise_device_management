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

#ifndef COMMON_EXTERNAL_INCLUDE_IEDM_OS_ACCOUNT_MANAGER_H
#define COMMON_EXTERNAL_INCLUDE_IEDM_OS_ACCOUNT_MANAGER_H

#include <vector>

#include "edm_errors.h"

namespace OHOS {
namespace EDM {
class IEdmOsAccountManager {
public:
    virtual ~IEdmOsAccountManager() = default;
    virtual ErrCode QueryActiveOsAccountIds(std::vector<int32_t> &ids) = 0;
    virtual ErrCode IsOsAccountExists(int32_t id, bool &isExist) = 0;
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_EXTERNAL_INCLUDE_IEDM_OS_ACCOUNT_MANAGER_H