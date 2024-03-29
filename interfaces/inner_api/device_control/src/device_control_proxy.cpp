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

#include "device_control_proxy.h"

#include "edm_log.h"
#include "func_code.h"
#include "message_parcel_utils.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<DeviceControlProxy> DeviceControlProxy::instance_ = nullptr;
std::mutex DeviceControlProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

DeviceControlProxy::DeviceControlProxy() {}

DeviceControlProxy::~DeviceControlProxy() {}

std::shared_ptr<DeviceControlProxy> DeviceControlProxy::GetDeviceControlProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<DeviceControlProxy> temp = std::make_shared<DeviceControlProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t DeviceControlProxy::ResetFactory(AppExecFwk::ElementName &admin)
{
    EDMLOGD("DeviceControlProxy::ResetFactory");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::RESET_FACTORY);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t DeviceControlProxy::Shutdown(AppExecFwk::ElementName &admin)
{
    EDMLOGD("DeviceControlProxy::Shutdown");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SHUTDOWN);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t DeviceControlProxy::Reboot(AppExecFwk::ElementName &admin)
{
    EDMLOGD("DeviceControlProxy::Reboot");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::REBOOT);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t DeviceControlProxy::LockScreen(AppExecFwk::ElementName &admin, int32_t userId)
{
    EDMLOGD("DeviceControlProxy::LockScreen");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::LOCK_SCREEN);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(userId);
    EDMLOGD("DeviceControlProxy LockScreen userId = %{public}d.", userId);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t DeviceControlProxy::OperateDevice(AppExecFwk::ElementName &admin, const OperateDeviceParam &param)
{
    EDMLOGD("DeviceControlProxy::OperateDevice");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::OPERATE_DEVICE);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    MessageParcelUtils::WriteOperateDeviceParam(param, data);
    EDMLOGD("DeviceControlProxy OperateDevice operate = %{public}s userId = %{public}d.", param.operate.c_str(),
        param.userId);
    return proxy->HandleDevicePolicy(funcCode, data);
}
} // namespace EDM
} // namespace OHOS