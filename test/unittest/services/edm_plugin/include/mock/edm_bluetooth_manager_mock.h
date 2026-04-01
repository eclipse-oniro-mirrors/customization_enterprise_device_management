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

#ifndef TEST_SERVICES_EDM_PLUGIN_EDM_BLUETOOTH_MANAGER_MOCK_H
#define TEST_SERVICES_EDM_PLUGIN_EDM_BLUETOOTH_MANAGER_MOCK_H

#include <gmock/gmock.h>

#include "iedm_bluetooth_manager.h"

namespace OHOS {
namespace EDM {
class EdmBluetoothManagerMock : public IEdmBluetoothManager {
public:
    ~EdmBluetoothManagerMock() override = default;
    MOCK_METHOD(bool, DisableBt, (), (override));
    MOCK_METHOD(bool, EnableBle, (), (override));
    MOCK_METHOD(std::string, GetLocalName, (), (override));
    MOCK_METHOD(int32_t, GetBtState, (), (override));
    MOCK_METHOD(int32_t, GetBtConnectionState, (), (override));
};
} // namespace EDM
} // namespace OHOS

#endif // TEST_SERVICES_EDM_PLUGIN_EDM_BLUETOOTH_MANAGER_MOCK_H