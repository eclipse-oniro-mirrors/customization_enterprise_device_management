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

#ifndef SERVICES_EDM_INCLUDE_ADMIN_SUB_SUPER_DEVICE_ADMIN_H
#define SERVICES_EDM_INCLUDE_ADMIN_SUB_SUPER_DEVICE_ADMIN_H

#include "admin.h"

namespace OHOS {
namespace EDM {
class SubSuperDeviceAdmin : public Admin {
public:
    SubSuperDeviceAdmin(const AdminInfo& adminInfo);
    ~SubSuperDeviceAdmin() override = default;
    bool IsEnterpriseAdminKeepAlive() const override;
    bool IsAllowedAcrossAccountSetPolicy() const override;
    bool HasPermissionToCallServiceCode(uint32_t interfaceCode) const override;
    bool HasPermissionToHandlePolicy(const std::string &policyName, FuncOperateType operateType) const override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_ADMIN_SUB_SUPER_DEVICE_ADMIN_H
