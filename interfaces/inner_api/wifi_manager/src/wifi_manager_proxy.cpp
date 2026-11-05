/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "edm_ipc_interface_code.h"
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

int32_t WifiManagerProxy::IsWifiActive(MessageParcel &data, bool &result)
{
    EDMLOGD("WifiManagerProxy::IsWifiActive");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
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
int32_t WifiManagerProxy::SetWifiProfile(MessageParcel &data)
{
    EDMLOGD("WifiManagerProxy::SetWifiProfile");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_WIFI_PROFILE);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t WifiManagerProxy::AddOrRemoveWifiList(MessageParcel &data, FuncOperateType operateType, EdmInterfaceCode code)
{
    EDMLOGD("WifiManagerProxy::AddOrRemoveWifiList");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)operateType, code);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t WifiManagerProxy::GetWifiList(MessageParcel &data, std::vector<WifiId> &result, EdmInterfaceCode policyCode)
{
    EDMLOGI("WifiManagerProxy::GetWifiList is %{public}d", policyCode);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(policyCode, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGD("WifiManagerProxy:GetWifiList fail. %{public}d", ret);
        return ret;
    }
    uint32_t size = reply.ReadUint32();
    if (size > EdmConstants::WIFI_LIST_MAX_SIZE) {
        EDMLOGE("WifiManagerProxy:GetWifiList size=[%{public}u] is too large", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("WifiManagerProxy:GetWifiList return size:%{public}u", size);
    for (uint32_t i = 0; i < size; i++) {
        WifiId wifiId;
        if (!WifiId::Unmarshalling(reply, wifiId)) {
            EDMLOGE("EnterpriseDeviceMgrProxy::GetEnterpriseInfo read parcel fail");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        result.emplace_back(wifiId);
    }
    return ERR_OK;
}
#endif

int32_t WifiManagerProxy::SetWifiDisabled(MessageParcel &data)
{
    EDMLOGD("WifiManagerProxy::SetWifiDisabled.");
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(data, EdmInterfaceCode::DISABLE_WIFI);
}

int32_t WifiManagerProxy::IsWifiDisabled(MessageParcel &data, bool &result)
{
    EDMLOGD("WifiManagerProxy::IsWifiDisabled");
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(data, EdmInterfaceCode::DISABLE_WIFI, result);
}

int32_t WifiManagerProxy::TurnOnWifi(MessageParcel &data)
{
    EDMLOGI("WifiManagerProxy::TurnOnWifi");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SWITCH_WIFI);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t WifiManagerProxy::TurnOffWifi(MessageParcel &data)
{
    EDMLOGI("WifiManagerProxy::TurnOffWifi");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::SWITCH_WIFI);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t WifiManagerProxy::AddAllowedHotspotClientList(MessageParcel &data)
{
    EDMLOGI("WifiManagerProxy::AddAllowedHotspotClientList");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    std::uint32_t funcCode = POLICY_FUNC_CODE_NEW((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::ALLOWED_HOTSPOT_CLIENT_LIST);
    return proxy->HandleDevicePolicyNew(funcCode, data);
}

int32_t WifiManagerProxy::RemoveAllowedHotspotClientList(MessageParcel &data)
{
    EDMLOGI("WifiManagerProxy::RemoveAllowedHotspotClientList");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    std::uint32_t funcCode = POLICY_FUNC_CODE_NEW((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::ALLOWED_HOTSPOT_CLIENT_LIST);
    return proxy->HandleDevicePolicyNew(funcCode, data);
}

int32_t WifiManagerProxy::GetAllowedHotspotClientList(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGI("WifiManagerProxy::GetAllowedHotspotClientList");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    int32_t ret = proxy->GetPolicyNew(EdmInterfaceCode::ALLOWED_HOTSPOT_CLIENT_LIST, data, reply);
    if (ret != ERR_OK) {
        EDMLOGW("WifiManagerProxy:GetAllowedHotspotClientList fail. %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

bool WifiManagerProxy::IsAllowedHotspotClientConnect(const std::string &macAddress)
{
    EDMLOGI("WifiManagerProxy::IsAllowedHotspotClientConnect");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return false;
    }
    if (!proxy->IsEdmEnabled()) {
        EDMLOGI("The device is not under control.");
        return true;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(EdmConstants::DEFAULT_USER_ID);
    data.WriteInt32(static_cast<int32_t>(QueryPolicy::ALL));
    data.WriteString(macAddress);
    int32_t ret = proxy->GetPolicyNew(EdmInterfaceCode::IS_ALLOWED_HOTSPOT_CLIENT_CONNECT, data, reply);
    if (ret != ERR_OK) {
        EDMLOGW("WifiManagerProxy:IsAllowedHotspotClientConnect GetPolicyNew fail. %{public}d", ret);
        return false;
    }
    bool isAllowed = false;
    reply.ReadBool(isAllowed);
    EDMLOGI("WifiManagerProxy:IsAllowedHotspotClientConnect result=%{public}d", isAllowed);
    return isAllowed;
}
} // namespace EDM
} // namespace OHOS
