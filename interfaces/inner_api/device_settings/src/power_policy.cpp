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

#include "power_policy.h"

#include "edm_log.h"
#include "parcel_macro.h"

namespace OHOS {
namespace EDM {
bool PowerPolicy::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, static_cast<uint32_t>(powerPolicyAction_));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, delayTime_);
    return true;
}

bool PowerPolicy::Unmarshalling(MessageParcel &parcel, PowerPolicy &powerPolicy)
{
    uint32_t action = parcel.ReadUint32();
    uint32_t delayTime = parcel.ReadUint32();
    if (!powerPolicy.SetPowerPolicyAction(action)) {
        return false;
    }
    powerPolicy.SetDelayTime(delayTime);
    return true;
}

void PowerPolicy::SetDelayTime(uint32_t delayTime)
{
    delayTime_ = delayTime;
}

bool PowerPolicy::SetPowerPolicyAction(uint32_t action)
{
    if (action >= static_cast<uint32_t>(PowerPolicyAction::NONE) &&
        action <= static_cast<uint32_t>(PowerPolicyAction::SHUTDOWN)) {
        powerPolicyAction_ = PowerPolicyAction(action);
        return true;
    }
    return false;
}

PowerPolicyAction PowerPolicy::GetPowerPolicyAction() const
{
    return powerPolicyAction_;
}

uint32_t PowerPolicy::GetDealyTime() const
{
    return delayTime_;
}
} // namespace EDM
} // namespace OHOS
