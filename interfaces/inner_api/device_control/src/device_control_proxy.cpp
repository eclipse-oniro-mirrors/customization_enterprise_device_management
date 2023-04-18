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

#include "device_control_proxy.h"
#include "edm_log.h"
#include "func_code.h"
#include "policy_info.h"

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
    EDMLOGD("DeviceInfoProxy::ResetFactory");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, RESET_FACTORY);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    return proxy->HandleDevicePolicy(funcCode, data);
}
} // namespace EDM
} // namespace OHOS