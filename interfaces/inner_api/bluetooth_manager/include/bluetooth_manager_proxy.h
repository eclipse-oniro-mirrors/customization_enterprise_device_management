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

#ifndef INTERFACES_INNER_API_BLUETOOTH_MANAGER_INCLUDE_BLUETOOTH_MANAGER_PROXY_H
#define INTERFACES_INNER_API_BLUETOOTH_MANAGER_INCLUDE_BLUETOOTH_MANAGER_PROXY_H

#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
struct BluetoothInfo {
    std::string name;
    int32_t state = 0;
    int32_t connectionState = 0;
};

class BluetoothManagerProxy {
public:
    static std::shared_ptr<BluetoothManagerProxy> GetBluetoothManagerProxy();
    int32_t GetBluetoothInfo(MessageParcel &data, BluetoothInfo &bluetoothInfo);
    int32_t SetBluetoothDisabled(MessageParcel &data);
    int32_t IsBluetoothDisabled(MessageParcel &data, bool &result);
    int32_t GetAllowedBluetoothDevices(const AppExecFwk::ElementName *admin, std::vector<std::string> &deviceIds);
    int32_t GetAllowedBluetoothDevices(MessageParcel &data, std::vector<std::string> &deviceIds);
    int32_t AddOrRemoveAllowedBluetoothDevices(MessageParcel &data, bool isAdd);

private:
    static std::shared_ptr<BluetoothManagerProxy> instance_;
    static std::once_flag flag_;
    int32_t AddOrRemoveAllowedBluetoothDevices(const AppExecFwk::ElementName &admin,
        const std::vector<std::string> &deviceIds, std::string function);
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_BLUETOOTH_MANAGER_INCLUDE_BLUETOOTH_MANAGER_PROXY_H