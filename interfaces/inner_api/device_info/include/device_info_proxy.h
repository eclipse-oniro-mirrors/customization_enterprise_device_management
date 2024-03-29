/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_DEVICE_INFO_INCLUDE_DEVICE_INFO_PROXY_H
#define INTERFACES_INNER_API_DEVICE_INFO_INCLUDE_DEVICE_INFO_PROXY_H
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
class DeviceInfoProxy {
public:
    DeviceInfoProxy();
    ~DeviceInfoProxy();
    static std::shared_ptr<DeviceInfoProxy> GetDeviceInfoProxy();
    int32_t GetDeviceSerial(AppExecFwk::ElementName &admin, std::string &info);
    int32_t GetDisplayVersion(AppExecFwk::ElementName &admin, std::string &info);
    int32_t GetDeviceName(AppExecFwk::ElementName &admin, std::string &info);
    int32_t GetDeviceInfoSync(AppExecFwk::ElementName &admin, const std::string &label, std::string &info);
private:
    int32_t GetDeviceInfo(AppExecFwk::ElementName &admin, std::string &info, int policyCode);
    static std::shared_ptr<DeviceInfoProxy> instance_;
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_DEVICE_INFO_INCLUDE_DEVICE_INFO_PROXY_H
