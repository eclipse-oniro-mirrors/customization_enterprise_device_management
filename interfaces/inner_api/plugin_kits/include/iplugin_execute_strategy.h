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

#ifndef INTERFACES_INNER_API_PLUGIN_KITS_IPLUGIN_EXECUTE_STRATEGY_H
#define INTERFACES_INNER_API_PLUGIN_KITS_IPLUGIN_EXECUTE_STRATEGY_H

#include "message_parcel.h"

#include "edm_errors.h"
#include "edm_log.h"
#include "handle_policy_data.h"

namespace OHOS {
namespace EDM {

class IPluginExecuteStrategy {
public:
    virtual ~IPluginExecuteStrategy() = default;
    virtual ErrCode OnGetExecute(std::uint32_t funcCode, std::string &policyData, MessageParcel &data,
        MessageParcel &reply, int32_t userId)
    {
        return ERR_OK;
    }
    virtual ErrCode OnSetExecute(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId)
    {
        return ERR_OK;
    }
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_PLUGIN_KITS_IPLUGIN_EXECUTE_STRATEGY_H
