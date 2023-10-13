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

#include "parcel.h"

namespace OHOS {
namespace EDM {
enum class PowerPolicyAction : uint32_t {
    ACTION_NONE = 0,
    ACTION_AUTO_SUSPEND,
    ACTION_FORCE_SUSPEND,
    ACTION_HIBERNATE,
    ACTION_SHUTDOWN,
};

class PowerPolicy : public Parcelable {
public:
    virtual bool Marshalling(Parcel &parcel) const override;
    static bool Unmarshalling(Parcel &parcel, PowerPolicy &powerPolicy);

    void inline SetDelayTime(uint32_t delayTime) { delayTime_ = delayTime; }
    bool inline SetPowerAction(uint32_t action)
    {
        if (action >= static_cast<uint32_t>(PowerPolicyAction::ACTION_NONE) &&
            action <= static_cast<uint32_t>(PowerPolicyAction::ACTION_SHUTDOWN)) {
            powerAction_ = PowerPolicyAction(action);
            return true;
        }
        return false;
    }

    [[nodiscard]] PowerPolicyAction GetPowerAction() const;
    [[nodiscard]] uint32_t GetDealyTime() const;

private:
    PowerPolicyAction powerAction_ = PowerPolicyAction::ACTION_AUTO_SUSPEND;
    uint32_t delayTime_ = 0;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_POWER_POLICY_H
