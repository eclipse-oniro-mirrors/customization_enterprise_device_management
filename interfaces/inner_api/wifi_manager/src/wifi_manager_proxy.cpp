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

#include "wifi_manager_proxy.h"
#include "edm_log.h"
#include "func_code.h"
#include "policy_info.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<WifiManagerProxy> WifiManagerProxy::instance_ = nullptr;
std::mutex WifiManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

WifiManagerProxy::WifiManagerProxy() {}

WifiManagerProxy::~WifiManagerProxy() {}

std::shared_ptr<WifiManagerProxy> WifiManagerProxy::GetWifiManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<WifiManagerProxy> temp = std::make_shared<WifiManagerProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t WifiManagerProxy::IsWifiActive(const AppExecFwk::ElementName &admin, bool &result)
{
    EDMLOGD("WifiManagerProxy::IsWifiActive");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel reply;
    proxy->GetPolicy(&admin, IS_WIFI_ACTIVE, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(result);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
