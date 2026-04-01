/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "edm_bluetooth_manager_impl.h"

#include "bluetooth_def.h"
#include "bluetooth_errorcode.h"
#include "bluetooth_host.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<EdmBluetoothManagerImpl> EdmBluetoothManagerImpl::instance_;
std::once_flag EdmBluetoothManagerImpl::flag_;

std::shared_ptr<EdmBluetoothManagerImpl> EdmBluetoothManagerImpl::GetInstance()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) EdmBluetoothManagerImpl());
        }
    });
    IEdmBluetoothManager::iInstance_ = instance_.get();
    return instance_;
}

bool EdmBluetoothManagerImpl::DisableBt()
{
    if (!Bluetooth::BluetoothHost::GetDefaultHost().IsBrEnabled()) {
        return true;
    }
    if (Bluetooth::BluetoothHost::GetDefaultHost().DisableBt() != Bluetooth::BT_NO_ERROR) {
        EDMLOGE("EdmBluetoothManagerImpl close bluetooth failed.");
        return false;
    }
    return true;
}

bool EdmBluetoothManagerImpl::EnableBle()
{
    if (Bluetooth::BluetoothHost::GetDefaultHost().EnableBle() != Bluetooth::BT_NO_ERROR) {
        EDMLOGE("EdmBluetoothManagerImpl open bluetooth failed.");
        return false;
    }
    return true;
}

std::string EdmBluetoothManagerImpl::GetLocalName()
{
    return Bluetooth::BluetoothHost::GetDefaultHost().GetLocalName();
}

int32_t EdmBluetoothManagerImpl::GetBtState()
{
    int32_t state = Bluetooth::BluetoothHost::GetDefaultHost().GetBtState();
    return TransformBluetoothState(state);
}

int32_t EdmBluetoothManagerImpl::GetBtConnectionState()
{
    int32_t connectionState = Bluetooth::BluetoothHost::GetDefaultHost().GetBtConnectionState();
    return TransformBluetoothConnectionState(connectionState);
}

int32_t EdmBluetoothManagerImpl::TransformBluetoothState(int32_t state)
{
    int32_t realState;
    switch (state) {
        case static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURNING_ON):
            realState = EdmBluetoothState::TURNING_ON;
            break;
        case static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON):
            realState = EdmBluetoothState::TURN_ON;
            break;
        case static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURNING_OFF):
            realState = EdmBluetoothState::TURNING_OFF;
            break;
        case static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_OFF):
            realState = EdmBluetoothState::TURN_OFF;
            break;
        default:
            realState = -1;
    }
    return realState;
}

int32_t EdmBluetoothManagerImpl::TransformBluetoothConnectionState(int32_t connectionState)
{
    int32_t realConnectionState;
    switch (connectionState) {
        case static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTING):
            realConnectionState = EdmBluetoothConnectionState::CONNECTING;
            break;
        case static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED):
            realConnectionState = EdmBluetoothConnectionState::CONNECTED;
            break;
        case static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTING):
            realConnectionState = EdmBluetoothConnectionState::DISCONNECTING;
            break;
        case static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTED):
            realConnectionState = EdmBluetoothConnectionState::DISCONNECTED;
            break;
        default:
            realConnectionState = -1;
    }
    return realConnectionState;
}
} // namespace EDM
} // namespace OHOS