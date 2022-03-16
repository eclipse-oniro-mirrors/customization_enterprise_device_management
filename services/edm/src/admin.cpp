/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "admin.h"

#include "edm_log.h"
#include "ent_info.h"
#include "string_ex.h"

namespace OHOS {
namespace EDM {
bool Admin::CheckPermission(const std::string &permission)
{
    EDMLOGD("Admin::CheckPermission");
    return std::any_of(adminInfo_.permission_.begin(), adminInfo_.permission_.end(),
        [&permission](const std::string &item) { return item == permission; });
}

AdminType Admin::GetAdminType()
{
    return AdminType::NORMAL;
}
} // namespace EDM
} // namespace OHOS