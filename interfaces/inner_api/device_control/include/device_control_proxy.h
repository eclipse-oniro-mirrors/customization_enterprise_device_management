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

#ifndef INTERFACES_INNER_API_DEVICE_CONTROL_INCLUDE_DEVICE_CONTROL_PROXY_H
#define INTERFACES_INNER_API_DEVICE_CONTROL_INCLUDE_DEVICE_CONTROL_PROXY_H

#include "enterprise_device_mgr_proxy.h"
#include "operate_device_param.h"

namespace OHOS {
namespace EDM {
class DeviceControlProxy {
public:
    DeviceControlProxy();
    ~DeviceControlProxy();
    static std::shared_ptr<DeviceControlProxy> GetDeviceControlProxy();
    int32_t ResetFactory(AppExecFwk::ElementName &admin);
    int32_t Shutdown(AppExecFwk::ElementName &admin);
    int32_t Reboot(AppExecFwk::ElementName &admin);
    int32_t LockScreen(AppExecFwk::ElementName &admin, int32_t userId);
    int32_t OperateDevice(AppExecFwk::ElementName &admin, const OperateDeviceParam &param);

private:
    static std::shared_ptr<DeviceControlProxy> instance_;
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_DEVICE_INFO_INCLUDE_DEVICE_INFO_PROXY_H
