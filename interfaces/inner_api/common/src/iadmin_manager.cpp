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

#include "iadmin_manager.h"

namespace OHOS {
namespace EDM {
IAdminManager* IAdminManager::adminManagerInstance_ = nullptr;

IAdminManager *IAdminManager::GetInstance()
{
    if (adminManagerInstance_ == nullptr) {
        adminManagerInstance_ = new (std::nothrow) IAdminManager();
    }
    return adminManagerInstance_;
}

AdminType IAdminManager::GetAdminTypeByName(const std::string &bundleName, int32_t userId)
{
    return AdminType::UNKNOWN;
}
} // namespace EDM
} // namespace OHOS
