/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "enterprise_device_mgr_proxy.h"

#include <iservice_registry.h>
#include <string_ex.h>

#include "admin_type.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_load_manager.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "func_code.h"
#include "parameters.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<EnterpriseDeviceMgrProxy> EnterpriseDeviceMgrProxy::instance_ = nullptr;
std::mutex EnterpriseDeviceMgrProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<EnterpriseDeviceMgrProxy> EnterpriseDeviceMgrProxy::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<EnterpriseDeviceMgrProxy> temp = std::make_shared<EnterpriseDeviceMgrProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

void EnterpriseDeviceMgrProxy::DestroyInstance()
{
    std::lock_guard<std::mutex> lock(mutexLock_);
    if (instance_ != nullptr) {
        instance_.reset();
    }
}

bool EnterpriseDeviceMgrProxy::IsEdmEnabled()
{
    std::string edmParaValue = system::GetParameter("persist.edm.edm_enable", "false");
    EDMLOGD("EnterpriseDeviceMgrProxy::GetParameter %{public}s", edmParaValue.c_str());
    return edmParaValue == "true";
}

bool EnterpriseDeviceMgrProxy::IsEdmExtEnabled()
{
    std::string edmExtParaValue = system::GetParameter("persist.edm.edm_ext_enable", "false");
    EDMLOGD("EnterpriseDeviceMgrProxy::GetParameter %{public}s", edmExtParaValue.c_str());
    return edmExtParaValue == "true";
}

ErrCode EnterpriseDeviceMgrProxy::EnableAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type,
    int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::EnableAdmin");
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->EnableAdmin(admin, entInfo, type, userId);
}

ErrCode EnterpriseDeviceMgrProxy::EnableDeviceAdmin(AppExecFwk::ElementName &admin)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::EnableDeviceAdmin");
#if defined(FEATURE_PC_ONLY)
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->EnableDeviceAdmin(admin);
#else
    EDMLOGW("EnterpriseDeviceMgrProxy::EnableDeviceAdmin Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

ErrCode EnterpriseDeviceMgrProxy::ReplaceSuperAdmin(AppExecFwk::ElementName &oldAdmin,
    AppExecFwk::ElementName &newAdmin, bool keepPolicy)
{
    EDMLOGI("EnterpriseDeviceMgrProxy::ReplaceSuperAdmin");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->ReplaceSuperAdmin(oldAdmin, newAdmin, keepPolicy);
}

ErrCode EnterpriseDeviceMgrProxy::DisableAdmin(AppExecFwk::ElementName &admin, int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::DisableAdmin");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->DisableAdmin(admin, userId);
}

ErrCode EnterpriseDeviceMgrProxy::DisableDeviceAdmin(AppExecFwk::ElementName &admin)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::DisableDeviceAdmin");
#if defined(FEATURE_PC_ONLY)
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->DisableDeviceAdmin(admin);
#else
    EDMLOGW("EnterpriseDeviceMgrProxy::DisableDeviceAdmin Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

ErrCode EnterpriseDeviceMgrProxy::DisableSuperAdmin(const std::string &bundleName)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::DisableSuperAdmin");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->DisableSuperAdmin(bundleName);
}

ErrCode EnterpriseDeviceMgrProxy::GetEnabledAdmin(AdminType type, std::vector<std::string> &enabledAdminList)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::GetEnabledAdmin");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->GetEnabledAdmin(type, enabledAdminList);
}

ErrCode EnterpriseDeviceMgrProxy::GetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::GetEnterpriseInfo");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->GetEnterpriseInfo(admin, entInfo);
}

ErrCode EnterpriseDeviceMgrProxy::SetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::SetEnterpriseInfo");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->SetEnterpriseInfo(admin, entInfo);
}

ErrCode EnterpriseDeviceMgrProxy::SetAdminRunningMode(AppExecFwk::ElementName &admin, uint32_t runningMode)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::SetAdminRunningMode");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->SetAdminRunningMode(admin, runningMode);
}

ErrCode EnterpriseDeviceMgrProxy::HandleManagedEvent(const AppExecFwk::ElementName &admin,
    const std::vector<uint32_t> &events, bool subscribe)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::SubscribeManagedEvent: %{public}d", subscribe);
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    if (subscribe) {
        return mgrService->SubscribeManagedEvent(admin, events);
    } else {
        return mgrService->UnsubscribeManagedEvent(admin, events);
    }
}

ErrCode EnterpriseDeviceMgrProxy::IsSuperAdmin(const std::string &bundleName, bool &result)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::IsSuperAdmin");
    result = false;
    if (!IsEdmEnabled()) {
        return ERR_OK;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->IsSuperAdmin(bundleName, result);
}

ErrCode EnterpriseDeviceMgrProxy::IsByodAdmin(const AppExecFwk::ElementName &admin, bool &result)
{
    EDMLOGI("EnterpriseDeviceMgrProxy::IsByodAdmin");
    result = false;
    if (!IsEdmEnabled()) {
        return ERR_OK;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    if (!mgrService) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return mgrService->IsByodAdmin(admin, result);
}

ErrCode EnterpriseDeviceMgrProxy::IsAdminEnabled(AppExecFwk::ElementName &admin, int32_t userId, bool &result)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::IsAdminEnabled");
    result = false;
    if (!IsEdmEnabled()) {
        return ERR_OK;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return false;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->IsAdminEnabled(admin, userId, result);
}

int32_t EnterpriseDeviceMgrProxy::IsPolicyDisabled(const AppExecFwk::ElementName *admin, int policyCode, bool &result,
    std::string permissionTag)
{
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(permissionTag);
    if (admin != nullptr) {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(admin);
    } else {
        if (!IsEdmEnabled()) {
            result = false;
            return ERR_OK;
        }
        data.WriteInt32(WITHOUT_ADMIN);
    }
    return IsPolicyDisabled(data, policyCode, result);
}

int32_t EnterpriseDeviceMgrProxy::IsPolicyDisabled(MessageParcel &data, uint32_t policyCode, bool &result)
{
    if (CheckDataInEdmDisabled(data)) {
        result = false;
        return ERR_OK;
    }
    MessageParcel reply;
    GetPolicy(policyCode, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool isSuccess = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!isSuccess) {
        EDMLOGE("IsPolicyDisabled:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(result);
    return ERR_OK;
}

int32_t EnterpriseDeviceMgrProxy::HandleDevicePolicy(int32_t policyCode, MessageParcel &data)
{
    MessageParcel reply;
    return HandleDevicePolicy(policyCode, data, reply);
}

bool EnterpriseDeviceMgrProxy::CheckDataInEdmDisabled(MessageParcel &data)
{
    data.ReadInterfaceToken();
    data.ReadInt32();
    data.ReadString();
    auto isAdmin = data.ReadInt32();
    data.RewindRead(0);
    if (isAdmin == WITHOUT_ADMIN && !IsEdmEnabled()) {
        return true;
    }
    return false;
}

int32_t EnterpriseDeviceMgrProxy::HandleDevicePolicy(int32_t policyCode, MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::HandleDevicePolicy");
    if (!IsEdmExtEnabled() && !IsEdmEnabled()) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageOption option;
    EDMLOGD("EnterpriseDeviceMgrProxy::handleDevicePolicy::sendRequest %{public}d", policyCode);
    ErrCode res = remote->SendRequest(policyCode, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:HandleDevicePolicy send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = ERR_INVALID_VALUE;
    reply.ReadInt32(ret);
    return ret;
}

ErrCode EnterpriseDeviceMgrProxy::AuthorizeAdmin(AppExecFwk::ElementName &admin, std::string &bundleName)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::AuthorizeAdmin");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->AuthorizeAdmin(admin, bundleName);
}

ErrCode EnterpriseDeviceMgrProxy::GetSuperAdmin(std::string &bundleName, std::string &abilityName)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::GetSuperAdmin");
    if (!IsEdmEnabled()) {
        return ERR_OK;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->GetSuperAdmin(bundleName, abilityName);
}

ErrCode EnterpriseDeviceMgrProxy::SetDelegatedPolicies(
    AppExecFwk::ElementName &parentAdmin, std::string &bundleName, std::vector<std::string> &policies)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::SetDelegatedPolicies");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->SetDelegatedPolicies(parentAdmin, bundleName, policies);
}

ErrCode EnterpriseDeviceMgrProxy::SetDelegatedPolicies(std::string &bundleName,
    std::vector<std::string> &policies, int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::SetDelegatedPolicies");
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->SetDelegatedPolicies(bundleName, policies, userId);
}

ErrCode EnterpriseDeviceMgrProxy::GetDelegatedPolicies(AppExecFwk::ElementName &parentAdmin,
    std::string &bundleOrPolicyName, uint32_t code, std::vector<std::string> &result)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::GetDelegatedPolicies");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    if (code == EdmInterfaceCode::GET_DELEGATED_POLICIES) {
        return mgrService->GetDelegatedPolicies(parentAdmin, bundleOrPolicyName, result);
    } else {
        return mgrService->GetDelegatedBundleNames(parentAdmin, bundleOrPolicyName, result);
    }
}

ErrCode EnterpriseDeviceMgrProxy::GetAdmins(std::vector<std::shared_ptr<AAFwk::Want>> &wants)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::GetAdmins");
    if (!IsEdmEnabled()) {
        return ERR_OK;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    return mgrService->GetAdmins(wants);
}

ErrCode EnterpriseDeviceMgrProxy::CheckAndGetAdminProvisionInfo(AppExecFwk::ElementName &admin,
    std::string &bundleName)
{
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, (std::uint32_t)EdmInterfaceCode::GET_ADMINPROVISION_INFO);
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    MessageParcel reply;
    MessageOption option;
    ErrCode res = remote->SendRequest(funcCode, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:CheckAndGetAdminProvisionInfo send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode = ERR_INVALID_VALUE;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:CheckAndGetAdminProvisionInfo get result code fail. %{public}d", resCode);
        return resCode;
    }
    bundleName = reply.ReadString();
    EDMLOGI("EnterpriseDeviceMgrProxy:CheckAndGetAdminProvisionInfo result. %{public}s", bundleName.c_str());
    return ERR_OK;
}

bool EnterpriseDeviceMgrProxy::GetPolicyValue(MessageParcel &data, uint32_t policyCode, std::string &policyData)
{
    MessageParcel reply;
    int32_t ret = ERR_INVALID_VALUE;
    if (!GetPolicy(policyCode, data, reply) || !reply.ReadInt32(ret) || ret != ERR_OK) {
        return false;
    }
    reply.ReadString(policyData);
    return true;
}

bool EnterpriseDeviceMgrProxy::GetPolicyArray(AppExecFwk::ElementName *admin, int policyCode,
    std::vector<std::string> &policyData, int32_t userId)
{
    MessageParcel reply;
    if (!GetPolicyData(admin, policyCode, userId, reply)) {
        return false;
    }
    int32_t size = reply.ReadInt32();
    EDMLOGD("EnterpriseDeviceMgrProxy::GetPolicyArray size: %{public}d.", size);
    return reply.ReadStringVector(&policyData);
}

bool EnterpriseDeviceMgrProxy::GetPolicyMap(AppExecFwk::ElementName *admin, int policyCode,
    std::map<std::string, std::string> &policyData, int32_t userId)
{
    MessageParcel reply;
    if (!GetPolicyData(admin, policyCode, userId, reply)) {
        return false;
    }
    std::vector<std::string> keys;
    if (!reply.ReadStringVector(&keys)) {
        EDMLOGE("EnterpriseDeviceMgrProxy::read map keys fail.");
        return false;
    }
    std::vector<std::string> values;
    if (!reply.ReadStringVector(&values)) {
        EDMLOGE("EnterpriseDeviceMgrProxy::read map values fail.");
        return false;
    }
    if (keys.size() != values.size()) {
        EDMLOGE("EnterpriseDeviceMgrProxy::read map fail.");
        return false;
    }
    policyData.clear();
    for (uint64_t i = 0; i < keys.size(); ++i) {
        policyData.insert(std::make_pair(keys.at(i), values.at(i)));
    }
    return true;
}

bool EnterpriseDeviceMgrProxy::GetPolicyData(AppExecFwk::ElementName *admin, int policyCode, int32_t userId,
    MessageParcel &reply)
{
    if (!IsEdmEnabled()) {
        return false;
    }
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    if (admin != nullptr) {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(admin);
    } else {
        data.WriteInt32(WITHOUT_ADMIN);
    }
    int32_t ret = ERR_INVALID_VALUE;
    return GetPolicy(policyCode, data, reply) && reply.ReadInt32(ret) && (ret == ERR_OK);
}

bool EnterpriseDeviceMgrProxy::GetPolicy(int policyCode, MessageParcel &data, MessageParcel &reply)
{
    if (policyCode == EdmInterfaceCode::PASSWORD_POLICY) {
        if (!IsEdmExtEnabled() && !IsEdmEnabled()) {
            reply.WriteInt32(EdmReturnErrCode::ADMIN_INACTIVE);
            return false;
        }
    } else if (!IsEdmEnabled()) {
        reply.WriteInt32(EdmReturnErrCode::ADMIN_INACTIVE);
        return false;
    }
    if (policyCode < 0) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy invalid policyCode:%{public}d", policyCode);
        return false;
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, (std::uint32_t)policyCode);
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return false;
    }
    MessageOption option;
    ErrCode res = remote->SendRequest(funcCode, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy send request fail.");
        return false;
    }
    return true;
}

void EnterpriseDeviceMgrProxy::GetEnabledAdmins(std::vector<std::string> &enabledAdminList)
{
    GetEnabledAdmins(AdminType::NORMAL, enabledAdminList);
}

void EnterpriseDeviceMgrProxy::GetEnabledSuperAdmin(std::string &enabledAdmin)
{
    std::vector<std::string> enabledAdminList;
    GetEnabledAdmins(AdminType::ENT, enabledAdminList);
    if (!enabledAdminList.empty()) {
        enabledAdmin = enabledAdminList[0];
    }
}

bool EnterpriseDeviceMgrProxy::IsSuperAdminExist()
{
    std::vector<std::string> enabledAdminList;
    GetEnabledAdmins(AdminType::ENT, enabledAdminList);
    return !enabledAdminList.empty();
}

sptr<IRemoteObject> EnterpriseDeviceMgrProxy::LoadAndGetEdmService()
{
    std::lock_guard<std::mutex> lock(mutexLock_);
    sptr<ISystemAbilityManager> sysAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sysAbilityMgr == nullptr) {
        EDMLOGE("EnterpriseDeviceMgrProxy::failed to get SystemAbilityManager");
        return nullptr;
    }
    auto objectSA = sysAbilityMgr->CheckSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    if (objectSA == nullptr) {
        EDMLOGI("EnterpriseDeviceMgrProxy::load sa from remote");
        return EdmLoadManager::GetInstance().LoadAndGetEdmService();
    }
    return EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
}

void EnterpriseDeviceMgrProxy::GetEnabledAdmins(AdminType type, std::vector<std::string> &enabledAdminList)
{
    if (!IsEdmEnabled()) {
        return;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    ErrCode res = mgrService->GetEnabledAdmin(type, enabledAdminList);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetEnabledAdmins GetEnabledAdmin fail.");
        return;
    }
}

int32_t EnterpriseDeviceMgrProxy::SetPolicyDisabled(const AppExecFwk::ElementName &admin, bool isDisabled,
    uint32_t policyCode, std::string permissionTag)
{
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, policyCode);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(permissionTag);
    data.WriteBool(isDisabled);
    return HandleDevicePolicy(funcCode, data);
}

int32_t EnterpriseDeviceMgrProxy::SetPolicyDisabled(MessageParcel &data,
    uint32_t policyCode)
{
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, policyCode);
    return HandleDevicePolicy(funcCode, data);
}

ErrCode EnterpriseDeviceMgrProxy::SetBundleInstallPolicies(std::vector<std::string> &bundles, int32_t userId,
    int32_t policyType)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::SetBundleInstallPolicies");
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    if (!mgrService) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return mgrService->SetBundleInstallPolicies(bundles, userId, policyType);
}
} // namespace EDM
} // namespace OHOS