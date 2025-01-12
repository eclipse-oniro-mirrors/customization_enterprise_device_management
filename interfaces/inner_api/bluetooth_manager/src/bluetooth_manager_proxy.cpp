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
std::once_flag BluetoothManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<BluetoothManagerProxy> BluetoothManagerProxy::GetBluetoothManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<BluetoothManagerProxy>();
        }
    });
    return instance_;
}

int32_t BluetoothManagerProxy::GetBluetoothInfo(MessageParcel &data, BluetoothInfo &bluetoothInfo)
{
    EDMLOGD("BluetoothManagerProxy::GetBluetoothInfo");
    MessageParcel reply;
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

int32_t BluetoothManagerProxy::SetBluetoothDisabled(MessageParcel &data)
{
    EDMLOGD("BluetoothManagerProxy::SetBluetoothDisabled");
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(data, EdmInterfaceCode::DISABLE_BLUETOOTH);
}

int32_t BluetoothManagerProxy::IsBluetoothDisabled(MessageParcel &data, bool &result)
{
    EDMLOGD("BluetoothManagerProxy::IsBluetoothDisabled");
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(data, EdmInterfaceCode::DISABLE_BLUETOOTH, result);
}

int32_t BluetoothManagerProxy::GetAllowedBluetoothDevices(const AppExecFwk::ElementName *admin,
    std::vector<std::string> &deviceIds)
{
    EDMLOGD("BluetoothManagerProxy::GetAllowedBluetoothDevices");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
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
    reply.ReadStringVector(&deviceIds);
    return ERR_OK;
}

int32_t BluetoothManagerProxy::GetAllowedBluetoothDevices(MessageParcel &data, std::vector<std::string> &deviceIds)
{
    EDMLOGD("BluetoothManagerProxy::GetAllowedBluetoothDevices");
    if (EnterpriseDeviceMgrProxy::GetInstance()->CheckDataInEdmDisabled(data)) {
        return ERR_OK;
    }
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES, data, reply);
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

int32_t BluetoothManagerProxy::AddOrRemoveAllowedBluetoothDevices(MessageParcel &data, bool isAdd)
{
    EDMLOGD("BluetoothManagerProxy::AddOrRemoveAllowedBluetoothDevices");
    FuncOperateType operateType = isAdd ? FuncOperateType::SET : FuncOperateType::REMOVE;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)operateType, EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}
} // namespace EDM
} // namespace OHOS