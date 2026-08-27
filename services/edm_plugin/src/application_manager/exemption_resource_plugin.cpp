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

#include "exemption_resource_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code.h"
#include "iplugin_manager.h"
#include "standby_service_client.h"
#include "resource_request.h"

namespace OHOS {
namespace EDM {
static const std::string FIXED_REASON = "EnterpriseDeviceManager";
static const std::string EDM_PROCESS_NAME = "edm";
static constexpr uint32_t STANDBY_RESOURCE_TYPE_NETWORK = 1;
static constexpr uint32_t REASON_NATIVE_API = 0;

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<ExemptionResourcePlugin>());

ExemptionResourcePlugin::ExemptionResourcePlugin()
{
    policyCode_ = EdmInterfaceCode::EXEMPTION_RESOURCE;
    policyName_ = PolicyName::POLICY_EXEMPTION_RESOURCE;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode ExemptionResourcePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    bool isRemove = FUNC_TO_OPERATE(funcCode) == static_cast<uint32_t>(FuncOperateType::REMOVE);
    uint32_t allowType = data.ReadUint32();
    std::string bundleName = data.ReadString();
    int32_t duration = isRemove ? 0 : data.ReadInt32();

    ErrCode ret = ValidateParams(isRemove, allowType, bundleName, duration);
    if (FAILED(ret)) {
        return ret;
    }

    int32_t uid = 0;
    ret = ResolveUid(bundleName, uid);
    if (FAILED(ret)) {
        return ret;
    }

    sptr<DevStandbyMgr::ResourceRequest> resourceRequest = new DevStandbyMgr::ResourceRequest(
        allowType, uid, EDM_PROCESS_NAME, duration, FIXED_REASON, REASON_NATIVE_API);
    auto &client = DevStandbyMgr::StandbyServiceClient::GetInstance();
    ErrCode standbyRet = ERR_OK;
    if (isRemove) {
        EDMLOGI("ExemptionResourcePlugin UnapplyAllowResource for bundle %{public}s, uid=%{public}d",
            bundleName.c_str(), uid);
        standbyRet = client.UnapplyAllowResource(resourceRequest);
    } else {
        EDMLOGI("ExemptionResourcePlugin ApplyAllowResource for bundle %{public}s, uid=%{public}d, duration=%{public}d",
            bundleName.c_str(), uid, duration);
        standbyRet = client.ApplyAllowResource(resourceRequest);
    }
    return ConvertStandbyErrCode(standbyRet);
}

ErrCode ExemptionResourcePlugin::ValidateParams(bool isRemove, uint32_t allowType,
    const std::string &bundleName, int32_t duration)
{
    if (allowType != STANDBY_RESOURCE_TYPE_NETWORK) {
        EDMLOGE("ExemptionResourcePlugin: invalid allowType %{public}u, only NETWORK(1) is supported", allowType);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (bundleName.empty()) {
        EDMLOGE("ExemptionResourcePlugin: bundleName is empty");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (!isRemove && duration <= 0) {
        EDMLOGE("ExemptionResourcePlugin: duration must > 0, got %{public}d", duration);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}

ErrCode ExemptionResourcePlugin::ResolveUid(const std::string &bundleName, int32_t &uid)
{
    auto osAccountMgr = externalManagerFactory_->CreateOsAccountManager();
    std::vector<int32_t> activeIds;
    ErrCode ret = osAccountMgr->QueryActiveOsAccountIds(activeIds);
    if (FAILED(ret) || activeIds.empty()) {
        EDMLOGE("ExemptionResourcePlugin: QueryActiveOsAccountIds failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    auto bundleMgr = externalManagerFactory_->CreateBundleManager();
    uid = bundleMgr->GetApplicationUid(bundleName, activeIds.at(0), 0);
    if (uid <= 0) {
        EDMLOGE("ExemptionResourcePlugin: failed to get uid for bundle %{public}s", bundleName.c_str());
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    return ERR_OK;
}

ErrCode ExemptionResourcePlugin::ConvertStandbyErrCode(ErrCode standbyErr)
{
    if (standbyErr == ERR_OK) {
        return ERR_OK;
    }
    EDMLOGW("ExemptionResourcePlugin: standby service failed, err=%{public}d", standbyErr);
    return EdmReturnErrCode::EXECUTE_TIME_OUT;
}
} // namespace EDM
} // namespace OHOS
