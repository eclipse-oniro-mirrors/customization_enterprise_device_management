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
    return proxy->SetPolicyDisabled(admin, disabled, EdmInterfaceCode::DISABLE_BLUETOOTH,
        EdmConstants::PERMISSION_TAG_VERSION_11);
}

int32_t BluetoothManagerProxy::IsBluetoothDisabled(const AppExecFwk::ElementName *admin, bool &result)
{
    EDMLOGD("BluetoothManagerProxy::IsBluetoothDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    return proxy->IsPolicyDisabled(admin, EdmInterfaceCode::DISABLE_BLUETOOTH, result,
        EdmConstants::PERMISSION_TAG_VERSION_11);
}

int32_t BluetoothManagerProxy::AddAllowedBluetoothDevices(const AppExecFwk::ElementName &admin,
    const std::vector<std::string> &deviceIds)
{
    return AddOrRemoveAllowedBluetoothDevices(admin, deviceIds, "AddAllowedBluetoothDevices");
}

int32_t BluetoothManagerProxy::GetAllowedBluetoothDevices(const AppExecFwk::ElementName *admin,
    std::vector<std::string> &deviceIds)
{
    EDMLOGD("BluetoothManagerProxy::GetAllowedBluetoothDevices");
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
    if (admin != nullptr) {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(admin);
    } else {
        if (!EnterpriseDeviceMgrProxy::GetInstance()->IsEdmEnabled()) {
            return ERR_OK;
        }
        data.WriteInt32(WITHOUT_ADMIN);
    }
    proxy->GetPolicy(EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > EdmConstants::BLUETOOTH_WHITELIST_MAX_SIZE) {
        EDMLOGE("BluetoothManagerProxy:GetAllowedBluetoothDevices size=[%{public}d] is too large.", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.ReadStringVector(&deviceIds);
    return ERR_OK;
}

int32_t BluetoothManagerProxy::RemoveAllowedBluetoothDevices(const AppExecFwk::ElementName &admin,
    const std::vector<std::string> &deviceIds)
{
    return AddOrRemoveAllowedBluetoothDevices(admin, deviceIds, "RemoveAllowedBluetoothDevices");
}

int32_t BluetoothManagerProxy::AddOrRemoveAllowedBluetoothDevices(const AppExecFwk::ElementName &admin,
    const std::vector<std::string> &deviceIds, std::string function)
{
    EDMLOGD("BluetoothManagerProxy::%{public}s", function.c_str());
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = 0;
    if (function == "AddAllowedBluetoothDevices") {
        funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    } else {
        funcCode =
            POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    }
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(deviceIds);
    return proxy->HandleDevicePolicy(funcCode, data);
}

} // namespace EDM
} // namespace OHOS