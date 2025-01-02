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
    int32_t GetDeviceSerial(MessageParcel &data, std::string &info);
    int32_t GetDisplayVersion(MessageParcel &data, std::string &info);
    int32_t GetDeviceName(MessageParcel &data, std::string &info);
    int32_t GetDeviceInfo(MessageParcel &data, const std::string &label, int policyCode, std::string &info);
private:
    static std::shared_ptr<DeviceInfoProxy> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_DEVICE_INFO_INCLUDE_DEVICE_INFO_PROXY_H
