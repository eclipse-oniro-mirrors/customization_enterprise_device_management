/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_manager_proxy.h"
#include "edm_log.h"
#include "func_code.h"
#include "policy_info.h"
#include "policy_type.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<BundleManagerProxy> BundleManagerProxy::instance_ = nullptr;
std::mutex BundleManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
constexpr int32_t MAX_SIZE = 200;

std::shared_ptr<BundleManagerProxy> BundleManagerProxy::GetBundleManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<BundleManagerProxy> temp = std::make_shared<BundleManagerProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t BundleManagerProxy::AddBundlesByPolicyType(AppExecFwk::ElementName &admin,
    std::vector<std::string> &bundles, int32_t userId, int32_t policyType)
{
    EDMLOGD("BundleManagerProxy::AddBundlesByPolicyType policyType =%{public}d", policyType);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = 0;
    switch (policyType) {
        case static_cast<int32_t>(PolicyType::ALLOW_INSTALL):
            funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ALLOWED_INSTALL_BUNDLES);
            break;
        case static_cast<int32_t>(PolicyType::DISALLOW_INSTALL):
            funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, DISALLOWED_INSTALL_BUNDLES);
            break;
        default:
            EDMLOGE("can not get policy type");
            return EdmReturnErrCode::PARAM_ERROR;
    }
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteParcelable(&admin);
    data.WriteStringVector(bundles);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t BundleManagerProxy::RemoveBundlesByPolicyType(AppExecFwk::ElementName &admin,
    std::vector<std::string> &bundles, int32_t userId, int32_t policyType)
{
    EDMLOGD("BundleManagerProxy::RemoveBundlesByPolicyType policyType =%{public}d", policyType);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = 0;
    switch (policyType) {
        case static_cast<int32_t>(PolicyType::ALLOW_INSTALL):
            funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, ALLOWED_INSTALL_BUNDLES);
            break;
        case static_cast<int32_t>(PolicyType::DISALLOW_INSTALL):
            funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, DISALLOWED_INSTALL_BUNDLES);
            break;
        default:
            EDMLOGE("can not get policy type");
            return EdmReturnErrCode::PARAM_ERROR;
    }
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteParcelable(&admin);
    data.WriteStringVector(bundles);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t BundleManagerProxy::GetBundlesByPolicyType(AppExecFwk::ElementName &admin, int32_t userId,
    std::vector<std::string> &bundles, int32_t policyType)
{
    EDMLOGD("BundleManagerProxy::GetAllowedOrDisallowedInstallBundles policyType =%{public}d", policyType);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    switch (policyType) {
        case static_cast<int32_t>(PolicyType::ALLOW_INSTALL):
            proxy->GetPolicy(ALLOWED_INSTALL_BUNDLES, data, reply);
            break;
        case static_cast<int32_t>(PolicyType::DISALLOW_INSTALL):
            proxy->GetPolicy(DISALLOWED_INSTALL_BUNDLES, data, reply);
            break;
        default:
            EDMLOGE("can not get policy type");
            return EdmReturnErrCode::PARAM_ERROR;
    }
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > MAX_SIZE) {
        EDMLOGE("bundles size=[%{public}d] is too large", size);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    reply.ReadStringVector(&bundles);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
