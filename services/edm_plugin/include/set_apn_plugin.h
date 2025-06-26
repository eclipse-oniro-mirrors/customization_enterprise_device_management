/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_SET_APN_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_SET_APN_PLUGIN_H

#include <message_parcel.h>

#include "iplugin.h"
#include "apn_utils.h"

namespace OHOS {
namespace EDM {
class SetApnPlugin : public IPlugin {
public:
    SetApnPlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override{};
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData,
        const std::string &mergeData, int32_t userId) override
    {
        return ERR_OK;
    };
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData, int32_t userId) override{};
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
private:
    ErrCode HandleAdd(MessageParcel &data);
    ErrCode HandleUpdate(MessageParcel &data);
    ErrCode HandleSetPrefer(MessageParcel &data);
    ErrCode HandleRemove(MessageParcel &data);
    ErrCode QueryId(MessageParcel &data, MessageParcel &reply);
    ErrCode QueryInfo(MessageParcel &data, MessageParcel &reply);
    std::map<std::string, std::string> ParserApnMap(MessageParcel &data, const char **pwd, int32_t *pwdLen);
    void GenerateApnMap(std::map<std::string, std::string> &apnInfo, MessageParcel &reply);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_SET_APN_PLUGIN_H
 