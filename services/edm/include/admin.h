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

#ifndef SERVICES_EDM_INCLUDE_ADMIN_H
#define SERVICES_EDM_INCLUDE_ADMIN_H

#include <string>
#include <vector>
#include "ability_info.h"
#include "admin_type.h"
#include "edm_errors.h"
#include "ent_info.h"
#include "managed_event.h"
#include "parcel_macro.h"

namespace OHOS {
namespace EDM {
struct AdminInfo {
    AdminType adminType_;
    std::string packageName_;
    std::string className_;
    EntInfo entInfo_;
    std::vector<std::string> permission_;
    std::vector<ManagedEvent> managedEvents_;
};

class Admin {
public:
    virtual bool CheckPermission(const std::string &permission);
    virtual AdminType GetAdminType();
    virtual ~Admin() = default;
    AdminInfo adminInfo_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_ADMIN_H
