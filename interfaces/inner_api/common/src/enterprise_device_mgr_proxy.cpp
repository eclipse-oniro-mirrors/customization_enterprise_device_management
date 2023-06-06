/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
const uint32_t GET_ENABLE_ADMIN = 5;

EnterpriseDeviceMgrProxy::EnterpriseDeviceMgrProxy() {}

EnterpriseDeviceMgrProxy::~EnterpriseDeviceMgrProxy() {}

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
        instance_ = nullptr;
    }
}

bool EnterpriseDeviceMgrProxy::IsEdmEnabled()
{
    std::string edmParaValue = system::GetParameter("persist.edm.edm_enable", "false");
    EDMLOGD("EnterpriseDeviceMgrProxy::GetParameter %{public}s", edmParaValue.c_str());
    return edmParaValue == "true";
}

ErrCode EnterpriseDeviceMgrProxy::EnableAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type,
    int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::EnableAdmin");
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteParcelable(&admin);
    data.WriteParcelable(&entInfo);
    data.WriteInt32(static_cast<int32_t>(type));
    data.WriteInt32(userId);
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::ADD_DEVICE_ADMIN, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:EnableAdmin send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode = ERR_OK;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:EnableAdmin get result code fail. %{public}d", resCode);
        return resCode;
    }
    return ERR_OK;
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteParcelable(&admin);
    data.WriteInt32(userId);
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::REMOVE_DEVICE_ADMIN, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:DisableAdmin send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode = ERR_OK;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:DisableAdmin get result code fail. %{public}d", resCode);
        return resCode;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrProxy::DisableSuperAdmin(std::string bundleName)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::DisableSuperAdmin");
    if (!IsEdmEnabled()) {
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    sptr<IRemoteObject> remote = LoadAndGetEdmService();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteString(bundleName);
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::REMOVE_SUPER_ADMIN, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:DisableSuperAdmin send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode = ERR_OK;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:DisableSuperAdmin get result code fail. %{public}d", resCode);
        return resCode;
    }
    return ERR_OK;
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(static_cast<int32_t>(type));
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::GET_ENABLED_ADMIN, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetEnabledAdmin send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode = ERR_OK;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetEnabledAdmin get result code fail. %{public}d", resCode);
        return resCode;
    }
    reply.ReadStringVector(&enabledAdminList);
    return ERR_OK;
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteParcelable(&admin);
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::GET_ENT_INFO, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetEnterpriseInfo send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode = ERR_OK;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetEnterpriseInfo get result code fail. %{public}d", resCode);
        return resCode;
    }
    std::unique_ptr<EntInfo> info(reply.ReadParcelable<EntInfo>());
    entInfo = *info;
    return ERR_OK;
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteParcelable(&admin);
    data.WriteParcelable(&entInfo);
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::SET_ENT_INFO, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:SetEnterpriseInfo send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode = ERR_OK;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:SetEnterpriseInfo get result code fail. %{public}d", resCode);
        return resCode;
    }
    return ERR_OK;
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteParcelable(&admin);
    data.WriteUInt32Vector(events);
    uint32_t policyCode = IEnterpriseDeviceMgr::SUBSCRIBE_MANAGED_EVENT;
    if (!subscribe) {
        policyCode = IEnterpriseDeviceMgr::UNSUBSCRIBE_MANAGED_EVENT;
    }
    ErrCode res = remote->SendRequest(policyCode, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:SubscribeManagedEvent send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t retCode;
    reply.ReadInt32(retCode);
    return retCode;
}

ErrCode EnterpriseDeviceMgrProxy::IsSuperAdmin(std::string bundleName, bool &result)
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteString(bundleName);
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::IS_SUPER_ADMIN, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:IsSuperAdmin send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode = ERR_OK;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:SetEnterpriseInfo get result code fail. %{public}d", resCode);
        return resCode;
    }
    reply.ReadBool(result);
    EDMLOGD("EnterpriseDeviceMgrProxy::IsSuperAdmin ret %{public}d", result);
    return ERR_OK;
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteParcelable(&admin);
    data.WriteInt32(userId);
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::IS_ADMIN_ENABLED, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:IsAdminEnabled send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode = ERR_OK;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:IsAdminEnabled get result code fail. %{public}d", resCode);
        return resCode;
    }
    reply.ReadBool(result);
    EDMLOGD("EnterpriseDeviceMgrProxy::IsAdminEnabled ret %{public}d", result);
    return ERR_OK;
}

bool EnterpriseDeviceMgrProxy::IsPolicyDisabled(AppExecFwk::ElementName *admin, int policyCode, bool &isDisabled,
    int32_t userId)
{
    MessageParcel reply;
    if (!GetPolicyData(admin, policyCode, userId, reply)) {
        return false;
    }
    reply.ReadBool(isDisabled);
    return true;
}

int32_t EnterpriseDeviceMgrProxy::HandleDevicePolicy(int32_t policyCode, MessageParcel &data)
{
    MessageParcel reply;
    return HandleDevicePolicy(policyCode, data, reply);
}

int32_t EnterpriseDeviceMgrProxy::HandleDevicePolicy(int32_t policyCode, MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::HandleDevicePolicy");
    if (!IsEdmEnabled()) {
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

bool EnterpriseDeviceMgrProxy::GetPolicyValue(AppExecFwk::ElementName *admin, int policyCode, std::string &policyData,
    int32_t userId)
{
    MessageParcel reply;
    if (!GetPolicyData(admin, policyCode, userId, reply)) {
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
    if (!reply.ReadStringVector(&policyData)) {
        return false;
    }
    return true;
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
    if (admin != nullptr) {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(admin);
    } else {
        data.WriteInt32(WITHOUT_ADMIN);
    }
    int32_t ret = ERR_INVALID_VALUE;
    if (!GetPolicy(policyCode, data, reply) || !reply.ReadInt32(ret) || (ret != ERR_OK)) {
        return false;
    }
    return true;
}

bool EnterpriseDeviceMgrProxy::GetPolicy(int policyCode, MessageParcel &data, MessageParcel &reply)
{
    if (!IsEdmEnabled()) {
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(static_cast<int32_t>(type));
    ErrCode res = remote->SendRequest(GET_ENABLE_ADMIN, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetEnabledAdmins send request fail.");
        return;
    }
    int32_t resCode = ERR_OK;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetEnabledAdmins get result code fail.");
        return;
    }
    std::vector<std::string> readArray;
    reply.ReadStringVector(&readArray);
    for (const std::string &item : readArray) {
        enabledAdminList.push_back(item);
    }
}
} // namespace EDM
} // namespace OHOS