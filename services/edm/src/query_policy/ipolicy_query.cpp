/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "ipolicy_query.h"

#include "admin_manager.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "element_name.h"
#include "func_code_utils.h"
#include "parameters.h"
#include "permission_checker.h"
#include "security_report.h"

namespace OHOS {
namespace EDM {

IPlugin::ApiType IPolicyQuery::GetApiType()
{
    return IPlugin::ApiType::PUBLIC;
}

bool IPolicyQuery::IsPolicySaved()
{
    return true;
}

ErrCode IPolicyQuery::GetBoolSystemParamSuccess(MessageParcel &reply, std::string paramKey, bool defaultValue)
{
    bool paraValue = system::GetBoolParameter(paramKey, defaultValue);
    EDMLOGI("IPolicyQuery OnGetPolicy paramKey result %{public}d", paraValue);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(paraValue);
    return ERR_OK;
}

ErrCode IPolicyQuery::GetPolicy(std::shared_ptr<PolicyManager> policyManager, uint32_t code, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGW("IPolicyQuery: GetPolicy start");
    std::string permissionTag = data.ReadString();
    ErrCode systemCallingCheck =
        PermissionChecker::GetInstance()->CheckSystemCalling(this->GetApiType(), permissionTag);
    if (FAILED(systemCallingCheck)) {
        return systemCallingCheck;
    }
    EDMLOGW("IPolicyQuery: GetPolicy read want");
    AppExecFwk::ElementName elementName;
    if (data.ReadInt32() == 0) {
        std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
        if (!admin) {
            EDMLOGW("GetDevicePolicy: ReadParcelable failed");
            return EdmReturnErrCode::PARAM_ERROR;
        }
        std::shared_ptr<Admin> deviceAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin->GetBundleName(),
            PermissionChecker::GetInstance()->GetCurrentUserId());
        if (deviceAdmin == nullptr) {
            return EdmReturnErrCode::ADMIN_INACTIVE;
        }
        IPlugin::PermissionType permissionType =
            PermissionChecker::GetInstance()->AdminTypeToPermissionType(deviceAdmin->GetAdminType());
        ErrCode ret = PermissionChecker::GetInstance()->CheckHandlePolicyPermission(FuncOperateType::GET,
            admin->GetBundleName(), this->GetPolicyName(), this->GetPermission(permissionType, permissionTag), userId);
        if (FAILED(ret)) {
            return ret;
        }
        elementName.SetBundleName(admin->GetBundleName());
        elementName.SetAbilityName(admin->GetAbilityName());
    }

    std::string policyName = this->GetPolicyName();
    std::string policyValue;
    if (this->IsPolicySaved()) {
        policyManager->GetPolicy(elementName.GetBundleName(), policyName, policyValue, userId);
    }
    ErrCode getRet = this->QueryPolicy(policyValue, data, reply, userId);
    CreateSecurityContent(elementName.GetBundleName(), elementName.GetAbilityName(), code, policyName, getRet);
    return getRet;
}

void IPolicyQuery::CreateSecurityContent(const std::string &bundleName, const std::string &abilityName, uint32_t code,
    const std::string &policyName, ErrCode errorCode)
{
    ReportInfo reportInfo = ReportInfo(FuncCodeUtils::GetOperateType(code), policyName, std::to_string(errorCode));
    SecurityReport::ReportSecurityInfo(bundleName, abilityName, reportInfo);
}
} // namespace EDM
} // namespace OHOS