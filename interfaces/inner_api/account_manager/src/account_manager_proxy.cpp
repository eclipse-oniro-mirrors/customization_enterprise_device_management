/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "account_manager_proxy.h"

#include "edm_log.h"
#include "func_code.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "os_account_info.h"
#endif

namespace OHOS {
namespace EDM {
std::shared_ptr<AccountManagerProxy> AccountManagerProxy::instance_ = nullptr;
std::mutex AccountManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

AccountManagerProxy::AccountManagerProxy() {}

AccountManagerProxy::~AccountManagerProxy() {}

std::shared_ptr<AccountManagerProxy> AccountManagerProxy::GetAccountManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<AccountManagerProxy> temp = std::make_shared<AccountManagerProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t AccountManagerProxy::DisallowAddLocalAccount(AppExecFwk::ElementName &admin, bool isDisallow)
{
#ifdef OS_ACCOUNT_EDM_ENABLE
    EDMLOGD("AccountManagerProxy::DisallowAddLocalAccount");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return proxy->SetPolicyDisabled(admin, isDisallow, EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT);
#else
    EDMLOGW("AccountManagerProxy::DisallowAddLocalAccount Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

int32_t AccountManagerProxy::IsAddLocalAccountDisallowed(AppExecFwk::ElementName *admin, bool &result)
{
#ifdef OS_ACCOUNT_EDM_ENABLE
    EDMLOGD("AccountManagerProxy::IsAddLocalAccountDisallowed");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return proxy->IsPolicyDisabled(admin, EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT, result);
#else
    EDMLOGW("AccountManagerProxy::IsAddLocalAccountDisallowed Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

int32_t AccountManagerProxy::DisallowAddOsAccountByUser(AppExecFwk::ElementName &admin, int32_t userId, bool isDisallow)
{
#ifdef OS_ACCOUNT_EDM_ENABLE
    EDMLOGD("AccountManagerProxy::DisallowAddOsAccountByUser");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOW_ADD_OS_ACCOUNT_BY_USER);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    std::vector<std::string> key {std::to_string(userId)};
    std::vector<std::string> value {isDisallow ? "true" : "false"};
    data.WriteStringVector(key);
    data.WriteStringVector(value);
    return proxy->HandleDevicePolicy(funcCode, data);
#else
    EDMLOGW("AccountManagerProxy::DisallowAddOsAccountByUser Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

int32_t AccountManagerProxy::IsAddOsAccountByUserDisallowed(AppExecFwk::ElementName *admin, int32_t userId,
    bool &result)
{
#ifdef OS_ACCOUNT_EDM_ENABLE
    EDMLOGD("AccountManagerProxy::IsAddOsAccountByUserDisallowed");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    if (admin != nullptr) {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(admin);
    } else {
        if (!EnterpriseDeviceMgrProxy::GetInstance()->IsEdmEnabled()) {
            result = false;
            return ERR_OK;
        }
        data.WriteInt32(WITHOUT_ADMIN);
    }
    data.WriteInt32(userId);
    MessageParcel reply;
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    proxy->GetPolicy(EdmInterfaceCode::DISALLOW_ADD_OS_ACCOUNT_BY_USER, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool isSuccess = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!isSuccess) {
        EDMLOGE("IsAddOsAccountByUserDisallowed:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(result);
    return ERR_OK;
#else
    EDMLOGW("AccountManagerProxy::IsAddOsAccountByUserDisallowed Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

#ifdef OS_ACCOUNT_EDM_ENABLE
int32_t AccountManagerProxy::AddOsAccount(AppExecFwk::ElementName &admin, std::string name, int32_t type,
    OHOS::AccountSA::OsAccountInfo &accountInfo, std::string &distributedInfoName, std::string &distributedInfoId)
{
    EDMLOGD("AccountManagerProxy::AddOsAccount");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    std::vector<std::string> key {name};
    std::vector<std::string> value {std::to_string(type)};
    data.WriteStringVector(key);
    data.WriteStringVector(value);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ADD_OS_ACCOUNT);
    ErrCode ret = proxy->HandleDevicePolicy(funcCode, data, reply);
    if (ret == ERR_OK) {
        OHOS::AccountSA::OsAccountInfo *result = OHOS::AccountSA::OsAccountInfo::Unmarshalling(reply);
        accountInfo = *result;
        distributedInfoName = reply.ReadString();
        distributedInfoId = reply.ReadString();
    }
    return ret;
}
#endif
} // namespace EDM
} // namespace OHOS
