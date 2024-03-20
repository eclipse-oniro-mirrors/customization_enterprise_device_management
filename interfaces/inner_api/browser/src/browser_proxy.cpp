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

#include "browser_proxy.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<BrowserProxy> BrowserProxy::instance_ = nullptr;
std::mutex BrowserProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<BrowserProxy> BrowserProxy::GetBrowserProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<BrowserProxy> temp = std::make_shared<BrowserProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t BrowserProxy::SetPolicies(const AppExecFwk::ElementName &admin, const std::string &appId,
    const std::string &policies)
{
    EDMLOGI("BrowserProxy::SetPolicies");
    if (appId.empty()) {
        EDMLOGE("BrowserProxy::SetPolicies appId is empty");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_BROWSER_POLICIES);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(EdmConstants::SET_POLICIES_TYPE);
    std::vector<std::string> key{appId};
    std::vector<std::string> value{policies};
    data.WriteStringVector(key);
    data.WriteStringVector(value);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t BrowserProxy::GetPolicies(std::string &policies)
{
    EDMLOGD("BrowserProxy::GetPolicies inner api");
    if (!EnterpriseDeviceMgrProxy::GetInstance()->IsEdmEnabled()) {
        EDMLOGD("BrowserProxy::GetPolicies edm service not start.");
        policies = "";
        return ERR_OK;
    }
    return GetPolicies(nullptr, "", policies);
}

int32_t BrowserProxy::GetPolicies(AppExecFwk::ElementName &admin, const std::string &appId, std::string &policies)
{
    EDMLOGD("BrowserProxy::GetPolicies");
    if (appId.empty()) {
        EDMLOGE("BrowserProxy::GetPolicies appId is empty.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    return GetPolicies(&admin, appId, policies);
}

int32_t BrowserProxy::GetPolicies(AppExecFwk::ElementName *admin, const std::string &appId, std::string &policies)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    if (admin == nullptr) {
        data.WriteInt32(WITHOUT_ADMIN);
    } else {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(admin);
    }
    data.WriteString(appId);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::SET_BROWSER_POLICIES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(policies);
    return ERR_OK;
}

int32_t BrowserProxy::SetPolicy(const AppExecFwk::ElementName &admin, const std::string &appId,
    const std::string &policyName, const std::string &policyValue)
{
    EDMLOGI("BrowserProxy::SetPolicy");
    if (appId.empty()) {
        EDMLOGE("BrowserProxy::SetPolicy appId is empty");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_BROWSER_POLICIES);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(EdmConstants::SET_POLICY_TYPE);
    std::vector<std::string> params{appId, policyName, policyValue};
    data.WriteStringVector(params);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}
} // namespace EDM
} // namespace OHOS
