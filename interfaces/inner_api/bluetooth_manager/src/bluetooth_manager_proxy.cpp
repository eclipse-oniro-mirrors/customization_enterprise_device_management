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

#include "bluetooth_manager_proxy.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "enterprise_device_mgr_proxy.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<BluetoothManagerProxy> BluetoothManagerProxy::instance_ = nullptr;
std::mutex BluetoothManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<BluetoothManagerProxy> BluetoothManagerProxy::GetBluetoothManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<BluetoothManagerProxy> temp = std::make_shared<BluetoothManagerProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t BluetoothManagerProxy::GetBluetoothInfo(const AppExecFwk::ElementName &admin, BluetoothInfo &bluetoothInfo)
{
    EDMLOGD("BluetoothManagerProxy::GetBluetoothInfo");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::GET_BLUETOOTH_INFO, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(bluetoothInfo.name);
    reply.ReadInt32(bluetoothInfo.state);
    reply.ReadInt32(bluetoothInfo.connectionState);
    return ERR_OK;
}

int32_t BluetoothManagerProxy::SetBluetoothDisabled(const AppExecFwk::ElementName &admin, bool disabled)
{
    EDMLOGD("BluetoothManagerProxy::SetBluetoothDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    return proxy->SetPolicyDisabled(admin, disabled, EdmInterfaceCode::DISABLE_BLUETOOTH);
}

int32_t BluetoothManagerProxy::IsBluetoothDisabled(const AppExecFwk::ElementName *admin, bool &result)
{
    EDMLOGD("BluetoothManagerProxy::IsBluetoothDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    return proxy->IsPolicyDisabled(admin, EdmInterfaceCode::DISABLE_BLUETOOTH, result);
}

int32_t BluetoothManagerProxy::SetBluetoothWhitelist(const AppExecFwk::ElementName &admin,
    std::vector<std::string> &whitelist)
{
    EDMLOGD("BluetoothManagerProxy::SetBluetoothWhitelist");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ALLOWED_BLUETOOTH_WHITELIST);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(whitelist);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t BluetoothManagerProxy::GetBluetoothWhitelist(const AppExecFwk::ElementName &admin,
    std::vector<std::string> &whitelist)
{
    EDMLOGD("BluetoothManagerProxy::GetBluetoothWhitelist");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    proxy->GetPolicy(EdmInterfaceCode::ALLOWED_BLUETOOTH_WHITELIST, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > EdmConstants::BLUETOOTH_WHITELIST_MAX_SIZE) {
        EDMLOGE("BluetoothManagerProxy:GetBluetoothWhitelist size=[%{public}d] is too large", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.ReadStringVector(&whitelist);
    return ERR_OK;
}

int32_t BluetoothManagerProxy::GetBluetoothWhitelist(std::vector<std::string> &whitelist)
{
    EDMLOGD("BluetoothManagerProxy::GetBluetoothWhitelist");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(WITHOUT_ADMIN);
    proxy->GetPolicy(EdmInterfaceCode::ALLOWED_BLUETOOTH_WHITELIST, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > EdmConstants::APPID_MAX_SIZE) {
        EDMLOGE("bundles size=[%{public}d] is too large", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.ReadStringVector(&whitelist);
    return ERR_OK;
}

int32_t BluetoothManagerProxy::RemoveBluetoothWhitelist(const AppExecFwk::ElementName &admin,
    std::vector<std::string> &whitelist)
{
    EDMLOGD("BluetoothManagerProxy::RemoveBluetoothWhitelist");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::ALLOWED_BLUETOOTH_WHITELIST);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(whitelist);
    return proxy->HandleDevicePolicy(funcCode, data);
}
} // namespace EDM
} // namespace OHOS