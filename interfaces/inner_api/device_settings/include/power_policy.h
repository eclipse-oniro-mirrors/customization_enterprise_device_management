/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_POWER_POLICY_H
#define INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_POWER_POLICY_H

#include "message_parcel.h"

namespace OHOS {
namespace EDM {
enum class PowerScene : uint32_t {
    TIME_OUT = 0,
};

enum class PowerPolicyAction : uint32_t {
    NONE = 0,
    AUTO_SUSPEND,
    FORCE_SUSPEND,
    HIBERNATE,
    SHUTDOWN,
};

class PowerPolicy {
public:
    bool Marshalling(MessageParcel &parcel) const;
    static bool Unmarshalling(MessageParcel &parcel, PowerPolicy &powerPolicy);

    void SetDelayTime(uint32_t delayTime);
    bool SetPowerPolicyAction(uint32_t action);

    [[nodiscard]] PowerPolicyAction GetPowerPolicyAction() const;
    [[nodiscard]] uint32_t GetDealyTime() const;

private:
    PowerPolicyAction powerPolicyAction_ = PowerPolicyAction::AUTO_SUSPEND;
    uint32_t delayTime_ = 0;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_POWER_POLICY_H
