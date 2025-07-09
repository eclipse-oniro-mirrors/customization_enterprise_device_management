/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_BLUETOOTH_MANAGER_INCLUDE_BLUETOOTH_MANAGER_ADDON_H
#define INTERFACES_KITS_BLUETOOTH_MANAGER_INCLUDE_BLUETOOTH_MANAGER_ADDON_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"
#include "bluetooth_manager_proxy.h"
#include "func_code.h"
#include "want.h"

namespace OHOS {
namespace EDM {

enum class BtProtocol : uint32_t {
    GATT = 0,
    SPP = 1,
    OPP = 2,
};

class BluetoothManagerAddon {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value GetBluetoothInfo(napi_env env, napi_callback_info info);
    static napi_value ConvertBluetoothInfo(napi_env env, BluetoothInfo &bluetoothInfo);
    static napi_value SetBluetoothDisabled(napi_env env, napi_callback_info info);
    static napi_value IsBluetoothDisabled(napi_env env, napi_callback_info info);
    static napi_value AddAllowedBluetoothDevices(napi_env env, napi_callback_info info);
    static napi_value GetAllowedBluetoothDevices(napi_env env, napi_callback_info info);
    static napi_value RemoveAllowedBluetoothDevices(napi_env env, napi_callback_info info);
    static napi_value AddOrRemoveBluetoothDevices(napi_env env, napi_callback_info info,
        FuncOperateType operateType, EdmInterfaceCode code);
    static napi_value AddDisallowedBluetoothDevices(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedBluetoothDevices(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedBluetoothDevices(napi_env env, napi_callback_info info);
    static napi_value GetBluetoothDevices(napi_env env, napi_callback_info info, EdmInterfaceCode policyCode);
    static napi_value TurnOnBluetooth(napi_env env, napi_callback_info info);
    static napi_value TurnOffBluetooth(napi_env env, napi_callback_info info);
    static napi_value TurnOnOrOffBluetooth(napi_env env, napi_callback_info info, bool isOpen);
    static napi_value AddDisallowedBluetoothProtocols(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedBluetoothProtocols(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedBluetoothProtocols(napi_env env, napi_callback_info info);
    static napi_value AddOrRemoveDisallowedBluetoothProtocols(napi_env env, napi_callback_info info,
        std::string function);
    static void CreateProtocolObject(napi_env env, napi_value value);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_BLUETOOTH_MANAGER_INCLUDE_BLUETOOTH_MANAGER_ADDON_H
