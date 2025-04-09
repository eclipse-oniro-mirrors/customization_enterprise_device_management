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

#ifndef SERVICES_EDM_INCLUDE_EDM_PERMISSION_CHECKER_H
#define SERVICES_EDM_INCLUDE_EDM_PERMISSION_CHECKER_H

#include <map>
#include <string>
#include <vector>

#include "admin.h"
#include "admin_type.h"
#include "external_manager_factory.h"
#include "iexternal_manager_factory.h"
#include "iplugin.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
class PermissionChecker : public std::enable_shared_from_this<PermissionChecker> {
public:
    static std::shared_ptr<PermissionChecker> GetInstance();

    ErrCode CheckCallerPermission(std::shared_ptr<Admin> admin, const std::string &permission, bool isNeedSuperAdmin);

    ErrCode CheckCallingUid(const std::string &bundleName);

    ErrCode CheckSystemCalling(IPlugin::ApiType apiType, const std::string &permissionTag);

    ErrCode GetAllPermissionsByAdmin(const std::string &bundleInfoName, AdminType adminType, int32_t userId,
        std::vector<std::string> &permissionList);

    ErrCode CheckHandlePolicyPermission(FuncOperateType operateType, const std::string &bundleName,
        const std::string &policyName, const std::string &permissionName, int32_t userId);

    ErrCode CheckAndUpdatePermission(std::shared_ptr<Admin> admin, Security::AccessToken::AccessTokenID tokenId,
        const std::string &permission, int32_t userId);

    bool CheckElementNullPermission(uint32_t code, const std::string &permissionName);

    bool CheckIsDebug();
    bool CheckIsSystemAppOrNative();
    bool CheckSpecialPolicyCallQuery(uint32_t code);
    bool CheckIsNativeTargetCallQuery(uint32_t code);
    bool VerifyCallingPermission(Security::AccessToken::AccessTokenID tokenId, const std::string &permissionName);
    virtual std::shared_ptr<IExternalManagerFactory> GetExternalManagerFactory();
    virtual ~PermissionChecker() = default;

    IPlugin::PermissionType AdminTypeToPermissionType(AdminType adminType);
    int32_t GetCurrentUserId();

private:
    PermissionChecker() = default;
    static std::once_flag flag_;
    static std::shared_ptr<PermissionChecker> instance_;
    static std::vector<uint32_t> supportAdminNullPolicyCode_;
    std::shared_ptr<IExternalManagerFactory> externalManagerFactory_ = std::make_shared<ExternalManagerFactory>();
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_PERMISSION_CHECKER_H
