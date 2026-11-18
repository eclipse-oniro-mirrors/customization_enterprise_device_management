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

#include "get_enterprise_re_signature_certificate_plugin.h"

#include <system_ability_definition.h>

#include "bundle_mgr_proxy.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_os_account_manager_impl.h"
#include "edm_sys_manager.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<GetEnterpriseReSignatureCertificatePlugin>());

GetEnterpriseReSignatureCertificatePlugin::GetEnterpriseReSignatureCertificatePlugin()
{
    policyCode_ = EdmInterfaceCode::GET_ENTERPRISE_RE_SIGNATURE_CERTIFICATE;
    policyName_ = PolicyName::POLICY_GET_ENTERPRISE_RE_SIGNATURE_CERTIFICATE;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode GetEnterpriseReSignatureCertificatePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGE("GetEnterpriseReSignatureCertificatePlugin::OnHandlePolicy unsupported");
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode GetEnterpriseReSignatureCertificatePlugin::GetBundleInstaller(
    sptr<AppExecFwk::IBundleInstaller> &iBundleInstaller, const std::string &methodName)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    auto iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        EDMLOGE("%{public}s: failed to get IBundleMgr", methodName.c_str());
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if (iBundleInstaller == nullptr) {
        EDMLOGE("%{public}s: failed to get IBundleInstaller", methodName.c_str());
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode GetEnterpriseReSignatureCertificatePlugin::CheckAccountId(int32_t accountId, int32_t userId,
    MessageParcel &reply)
{
    if (accountId < EdmConstants::DEFAULT_USER_ID) {
        EDMLOGE("GetEnterpriseReSignatureCertificatePlugin::CheckAccountId invalid accountId: %{public}d", accountId);
        reply.WriteInt32(EdmReturnErrCode::UID_INVALID);
        return EdmReturnErrCode::UID_INVALID;
    }
    if (accountId != userId) {
        EDMLOGE("GetEnterpriseReSignatureCertificatePlugin::CheckAccountId cross user not allowed, "
            "accountId: %{public}d, userId: %{public}d", accountId, userId);
        reply.WriteInt32(EdmReturnErrCode::CROSS_USER_NOT_ALLOWED);
        return EdmReturnErrCode::CROSS_USER_NOT_ALLOWED;
    }
    bool isExist = false;
    ErrCode ret = std::make_shared<EdmOsAccountManagerImpl>()->IsOsAccountExists(accountId, isExist);
    if (FAILED(ret) || !isExist) {
        EDMLOGE("GetEnterpriseReSignatureCertificatePlugin::CheckAccountId account not exist: %{public}d", accountId);
        reply.WriteInt32(EdmReturnErrCode::UID_INVALID);
        return EdmReturnErrCode::UID_INVALID;
    }
    return ERR_OK;
}

void GetEnterpriseReSignatureCertificatePlugin::WriteCertInfos(
    const std::vector<AppExecFwk::EnterpriseCertInfo> &certInfos, MessageParcel &reply)
{
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(static_cast<int32_t>(certInfos.size()));
    for (const auto &certInfo : certInfos) {
        reply.WriteString(certInfo.certAlias);
        reply.WriteString(certInfo.enterpriseName);
        reply.WriteInt64(certInfo.notAfter);
    }
}

ErrCode GetEnterpriseReSignatureCertificatePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("GetEnterpriseReSignatureCertificatePlugin::OnGetPolicy");
    int32_t accountId = data.ReadInt32();
    ErrCode ret = CheckAccountId(accountId, userId, reply);
    if (ret != ERR_OK) {
        return ret;
    }
    sptr<AppExecFwk::IBundleInstaller> iBundleInstaller = nullptr;
    ret = GetBundleInstaller(iBundleInstaller, __func__);
    if (ret != ERR_OK) {
        reply.WriteInt32(ret);
        return ret;
    }
    std::vector<AppExecFwk::EnterpriseCertInfo> certInfos;
    ret = iBundleInstaller->GetEnterpriseReSignatureCertInfo(accountId, certInfos);
    if (ret != ERR_OK) {
        EDMLOGE("GetEnterpriseReSignatureCertificatePlugin: GetEnterpriseReSignatureCertInfo failed %{public}d", ret);
        reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    for (const auto &certInfo : certInfos) {
        if (certInfo.certAlias.empty() || certInfo.enterpriseName.empty()) {
            EDMLOGE("GetEnterpriseReSignatureCertificatePlugin: empty certificate field, alias '%{public}s', "
                "enterpriseName '%{public}s'", certInfo.certAlias.c_str(), certInfo.enterpriseName.c_str());
            reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    WriteCertInfos(certInfos, reply);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
