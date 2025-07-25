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
std::once_flag DeviceControlProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

DeviceControlProxy::DeviceControlProxy() {}

DeviceControlProxy::~DeviceControlProxy() {}

std::shared_ptr<DeviceControlProxy> DeviceControlProxy::GetDeviceControlProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<DeviceControlProxy>();
        }
    });
    return instance_;
}

int32_t DeviceControlProxy::ResetFactory(MessageParcel &data)
{
    EDMLOGD("DeviceControlProxy::ResetFactory");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::RESET_FACTORY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t DeviceControlProxy::Shutdown(MessageParcel &data)
{
    EDMLOGD("DeviceControlProxy::Shutdown");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SHUTDOWN);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t DeviceControlProxy::Reboot(MessageParcel &data)
{
    EDMLOGD("DeviceControlProxy::Reboot");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::REBOOT);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t DeviceControlProxy::LockScreen(AppExecFwk::ElementName &admin, int32_t userId)
{
    EDMLOGD("DeviceControlProxy::LockScreen");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::LOCK_SCREEN);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(userId);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t DeviceControlProxy::OperateDevice(AppExecFwk::ElementName &admin, const OperateDeviceParam &param)
{
    EDMLOGD("DeviceControlProxy::OperateDevice");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::OPERATE_DEVICE);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    MessageParcelUtils::WriteOperateDeviceParam(param, data);
    EDMLOGD("DeviceControlProxy OperateDevice operate = %{public}s.", param.operate.c_str());
    return proxy->HandleDevicePolicy(funcCode, data);
}
} // namespace EDM
} // namespace OHOS