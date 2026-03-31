/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EDM_BLUETOOTH_MANAGER_IMPL_H
#define SERVICES_EDM_INCLUDE_EDM_BLUETOOTH_MANAGER_IMPL_H

#include <memory>
#include <mutex>

#include "iedm_bluetooth_manager.h"

namespace OHOS {
namespace EDM {
enum EdmBluetoothState {
    TURN_OFF,
    TURNING_ON,
    TURN_ON,
    TURNING_OFF,
};

enum EdmBluetoothConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
};

class EdmBluetoothManagerImpl : public IEdmBluetoothManager {
public:
    static std::shared_ptr<EdmBluetoothManagerImpl> GetInstance();
    ~EdmBluetoothManagerImpl() override = default;
    bool DisableBt() override;
    bool EnableBle() override;
    std::string GetLocalName() override;
    int32_t GetBtState() override;
    int32_t GetBtConnectionState() override;

private:
    EdmBluetoothManagerImpl() = default;
    static std::once_flag flag_;
    static std::shared_ptr<EdmBluetoothManagerImpl> instance_;
    int32_t TransformBluetoothState(int32_t state);
    int32_t TransformBluetoothConnectionState(int32_t connectionState);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_BLUETOOTH_MANAGER_IMPL_H