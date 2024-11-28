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

#include "edm_constants.h"
#include "edm_log.h"
#include "func_code.h"
#include "message_parcel_utils.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<WifiManagerProxy> WifiManagerProxy::instance_ = nullptr;
std::once_flag WifiManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

WifiManagerProxy::WifiManagerProxy() {}

WifiManagerProxy::~WifiManagerProxy() {}

std::shared_ptr<WifiManagerProxy> WifiManagerProxy::GetWifiManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<WifiManagerProxy>();
        }
    });
    return instance_;
}

int32_t WifiManagerProxy::IsWifiActive(const AppExecFwk::ElementName &admin, bool &result, bool isSync)
{
    EDMLOGD("WifiManagerProxy::IsWifiActive");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(isSync ? EdmConstants::PERMISSION_TAG_VERSION_12 : EdmConstants::PERMISSION_TAG_VERSION_11);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    proxy->GetPolicy(EdmInterfaceCode::IS_WIFI_ACTIVE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(result);
    return ERR_OK;
}
#ifdef WIFI_EDM_ENABLE
int32_t WifiManagerProxy::SetWifiProfile(const AppExecFwk::ElementName &admin, Wifi::WifiDeviceConfig &config,
    WifiPassword &pwd, bool isSync)
{
    EDMLOGD("WifiManagerProxy::SetWifiProfile");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_WIFI_PROFILE);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(isSync ? EdmConstants::PERMISSION_TAG_VERSION_12 : EdmConstants::PERMISSION_TAG_VERSION_11);
    MessageParcelUtils::WriteWifiDeviceConfig(config, data, pwd);
    return proxy->HandleDevicePolicy(funcCode, data);
}
#endif

int32_t WifiManagerProxy::SetWifiDisabled(const AppExecFwk::ElementName &admin, const bool &isDisabled)
{
    EDMLOGD("WifiManagerProxy::SetWifiDisabled. isDisable: %{public}d", isDisabled);
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(admin, isDisabled,
        EdmInterfaceCode::DISABLE_WIFI, EdmConstants::PERMISSION_TAG_VERSION_11);
}

int32_t WifiManagerProxy::IsWifiDisabled(AppExecFwk::ElementName *admin, bool &result)
{
    EDMLOGD("WifiManagerProxy::IsWifiDisabled");
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(admin, EdmInterfaceCode::DISABLE_WIFI, result,
        EdmConstants::PERMISSION_TAG_VERSION_11);
}
} // namespace EDM
} // namespace OHOS
