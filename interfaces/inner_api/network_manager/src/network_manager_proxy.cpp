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

#include "network_manager_proxy.h"
#include "edm_log.h"
#include "func_code.h"
#include "policy_info.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<NetworkManagerProxy> NetworkManagerProxy::instance_ = nullptr;
std::mutex NetworkManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
constexpr int32_t MAX_SIZE = 16;

NetworkManagerProxy::NetworkManagerProxy() {}

NetworkManagerProxy::~NetworkManagerProxy() {}

std::shared_ptr<NetworkManagerProxy> NetworkManagerProxy::GetNetworkManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<NetworkManagerProxy> temp = std::make_shared<NetworkManagerProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t NetworkManagerProxy::GetAllNetworkInterfaces(const AppExecFwk::ElementName &admin,
    std::vector<std::string> &networkInterface)
{
    EDMLOGD("NetworkManagerProxy::GetAllNetworkInterfaces");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(0); // without userid
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    proxy->GetPolicy(GET_NETWORK_INTERFACES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > MAX_SIZE) {
        EDMLOGE("networkInterface size=[%{public}d] is too large", size);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    reply.ReadStringVector(&networkInterface);
    return ERR_OK;
}

int32_t NetworkManagerProxy::GetIpOrMacAddress(const AppExecFwk::ElementName &admin,
    const std::string &networkInterface, int policyCode, std::string &info)
{
    EDMLOGD("NetworkManagerProxy::GetIpOrMacAddress");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(0); // without userid
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    data.WriteString(networkInterface);
    proxy->GetPolicy(policyCode, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(info);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
