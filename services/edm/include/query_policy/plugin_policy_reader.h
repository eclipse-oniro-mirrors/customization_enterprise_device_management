/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_QUERY_POLICY_PLUGIN_POLICY_READER_H
#define SERVICES_EDM_INCLUDE_QUERY_POLICY_PLUGIN_POLICY_READER_H

#include <string>

#include "edm_errors.h"
#include "ipolicy_query.h"
#include "message_parcel.h"
#include "policy_manager.h"

namespace OHOS {
namespace EDM {
class PluginPolicyReader {
public:
    static std::shared_ptr<PluginPolicyReader> GetInstance();

    ErrCode GetPolicyByCode(std::shared_ptr<PolicyManager> policyManager, uint32_t code, MessageParcel &data,
        MessageParcel &reply, int32_t userId);

    ErrCode GetPolicyByCodeInner(std::shared_ptr<PolicyManager> policyManager, uint32_t code, MessageParcel &data,
        MessageParcel &reply, int32_t userId);

    ErrCode GetPolicyQuery(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQueryFirst(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQuerySecond(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQueryThird(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQueryFourth(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQueryFifthPartOne(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQueryFifthPartTwo(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQuerySixth(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQuerySeventh(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQueryEighth(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQueryNinth(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);
    ErrCode GetPolicyQueryTenth(std::shared_ptr<IPolicyQuery> &obj, uint32_t code);

private:
    static std::shared_ptr<PluginPolicyReader> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_QUERY_POLICY_PLUGIN_POLICY_READER_H
