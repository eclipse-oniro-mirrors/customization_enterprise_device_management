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

#include "enterprise_device_mgr_proxy.h"
#include <iservice_registry.h>
#include <string_ex.h>

#include "admin_type.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "func_code.h"
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

ErrCode EnterpriseDeviceMgrProxy::EnableAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type,
    int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::EnableAdmin");
    sptr<IRemoteObject> remote = GetRemoteObject();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteParcelable(&admin);
    data.WriteParcelable(&entInfo);
    data.WriteUint32(type);
    data.WriteInt32(userId);
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::ADD_DEVICE_ADMIN, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:EnableAdmin send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:EnableAdmin get result code fail. %{public}d", resCode);
        return resCode;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrProxy::DisableAdmin(AppExecFwk::ElementName &admin, int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::DisableAdmin");
    sptr<IRemoteObject> remote = GetRemoteObject();
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
    int32_t resCode;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:DisableAdmin get result code fail. %{public}d", resCode);
        return resCode;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrProxy::DisableSuperAdmin(std::string bundleName)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::DisableSuperAdmin");
    sptr<IRemoteObject> remote = GetRemoteObject();
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
    int32_t resCode;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:DisableSuperAdmin get result code fail. %{public}d", resCode);
        return resCode;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrProxy::GetEnabledAdmin(AdminType type, std::vector<std::u16string> &enabledAdminList)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::GetEnabledAdmin");
    sptr<IRemoteObject> remote = GetRemoteObject();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteUint32(type);
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::GET_ENABLED_ADMIN, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetEnabledAdmin send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t resCode;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetEnabledAdmin get result code fail. %{public}d", resCode);
        return resCode;
    }
    reply.ReadString16Vector(&enabledAdminList);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrProxy::GetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::GetEnterpriseInfo");
    sptr<IRemoteObject> remote = GetRemoteObject();
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
    int32_t resCode;
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
    sptr<IRemoteObject> remote = GetRemoteObject();
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
    int32_t resCode;
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
    sptr<IRemoteObject> remote = GetRemoteObject();
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

bool EnterpriseDeviceMgrProxy::IsSuperAdmin(std::string bundleName)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::IsSuperAdmin");
    sptr<IRemoteObject> remote = GetRemoteObject();
    if (!remote) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteString(bundleName);
    ErrCode res = remote->SendRequest(IEnterpriseDeviceMgr::IS_SUPER_ADMIN, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:IsSuperAdmin send request fail. %{public}d", res);
        return false;
    }
    bool ret = false;
    reply.ReadBool(ret);
    EDMLOGD("EnterpriseDeviceMgrProxy::IsSuperAdmin ret %{public}d", ret);
    return ret;
}

bool EnterpriseDeviceMgrProxy::IsAdminEnabled(AppExecFwk::ElementName &admin, int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::IsAdminEnabled");
    sptr<IRemoteObject> remote = GetRemoteObject();
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
        return false;
    }
    bool ret = false;
    reply.ReadBool(ret);
    EDMLOGD("EnterpriseDeviceMgrProxy::IsAdminEnabled ret %{public}d", ret);
    return ret;
}

bool EnterpriseDeviceMgrProxy::IsPolicyDisable(int policyCode, bool &isDisabled)
{
    MessageParcel reply;
    if (!GetPolicy(policyCode, reply)) {
        isDisabled = false;
        return false;
    } else {
        isDisabled = reply.ReadBool();
    }
    return true;
}

int32_t EnterpriseDeviceMgrProxy::HandleDevicePolicy(int32_t policyCode, MessageParcel &data)
{
    EDMLOGD("EnterpriseDeviceMgrProxy::HandleDevicePolicy");
    sptr<IRemoteObject> remote = GetRemoteObject();
    if (!remote) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel reply;
    MessageOption option;
    EDMLOGD("EnterpriseDeviceMgrProxy::handleDevicePolicy::sendRequest %{public}d", policyCode);
    ErrCode res = remote->SendRequest(policyCode, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:HandleDevicePolicy send request fail. %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = ERR_OK;
    reply.ReadInt32(ret);
    return ret;
}

bool EnterpriseDeviceMgrProxy::GetPolicyValue(int policyCode, std::string &policyData)
{
    MessageParcel reply;
    if (!GetPolicy(policyCode, reply)) {
        return false;
    }
    policyData = Str16ToStr8(reply.ReadString16());
    return true;
}

bool EnterpriseDeviceMgrProxy::GetPolicyArray(int policyCode, std::vector<std::string> &policyData)
{
    MessageParcel reply;
    if (!GetPolicy(policyCode, reply)) {
        return false;
    }
    std::vector<std::u16string> readVector16;
    if (!reply.ReadString16Vector(&readVector16)) {
        return false;
    }
    policyData.clear();
    if (!readVector16.empty()) {
        for (const auto &str16 : readVector16) {
            policyData.push_back(Str16ToStr8(str16));
        }
    }
    return true;
}

bool EnterpriseDeviceMgrProxy::GetPolicyConfig(int policyCode, std::map<std::string, std::string> &policyData)
{
    MessageParcel reply;
    if (!GetPolicy(policyCode, reply)) {
        return false;
    }
    std::vector<std::u16string> keys16;
    std::vector<std::u16string> values16;
    if (!reply.ReadString16Vector(&keys16)) {
        EDMLOGE("EnterpriseDeviceMgrProxy::read map keys fail.");
        return false;
    }
    if (!reply.ReadString16Vector(&values16)) {
        EDMLOGE("EnterpriseDeviceMgrProxy::read map values fail.");
        return false;
    }
    if (keys16.size() != values16.size()) {
        EDMLOGE("EnterpriseDeviceMgrProxy::read map fail.");
        return false;
    }
    std::vector<std::string> keys;
    std::vector<std::string> values;
    for (const std::u16string &key : keys16) {
        keys.push_back(Str16ToStr8(key));
    }
    for (const std::u16string &value : values16) {
        values.push_back(Str16ToStr8(value));
    }
    policyData.clear();
    for (uint64_t i = 0; i < keys.size(); ++i) {
        policyData.insert(std::make_pair(keys.at(i), values.at(i)));
    }
    return true;
}

bool EnterpriseDeviceMgrProxy::GetPolicy(int policyCode, MessageParcel &reply)
{
    if (policyCode < 0) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy invalid policyCode:%{public}d", policyCode);
        return false;
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, (std::uint32_t)policyCode);
    sptr<IRemoteObject> remote = GetRemoteObject();
    if (!remote) {
        return false;
    }
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    MessageOption option;
    ErrCode res = remote->SendRequest(funcCode, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy send request fail.");
        return false;
    }
    std::int32_t requestRes = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(requestRes) && (requestRes == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", requestRes);
    }
    return blRes;
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

sptr<IRemoteObject> EnterpriseDeviceMgrProxy::GetRemoteObject()
{
    std::lock_guard<std::mutex> lock(mutexLock_);
    sptr<IRemoteObject> remote = EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    return remote;
}

void EnterpriseDeviceMgrProxy::GetEnabledAdmins(std::uint32_t type, std::vector<std::string> &enabledAdminList)
{
    sptr<IRemoteObject> remote = GetRemoteObject();
    if (!remote) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteUint32(type);
    ErrCode res = remote->SendRequest(GET_ENABLE_ADMIN, data, reply, option);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetEnabledAdmins send request fail.");
        return;
    }
    int32_t resCode;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetEnabledAdmins get result code fail.");
        return;
    }
    std::vector<std::u16string> readArray;
    reply.ReadString16Vector(&readArray);
    for (const std::u16string &item : readArray) {
        enabledAdminList.push_back(Str16ToStr8(item));
    }
}
} // namespace EDM
} // namespace OHOS