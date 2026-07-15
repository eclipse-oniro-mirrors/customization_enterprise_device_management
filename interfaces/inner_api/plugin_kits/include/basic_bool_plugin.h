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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_BASIC_BOOL_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_BASIC_BOOL_PLUGIN_H

#include "message_parcel.h"

#include "edm_errors.h"
#include "iplugin.h"

namespace OHOS {
namespace EDM {
class BasicBoolPlugin : public IPlugin {
public:
    BasicBoolPlugin() = default;

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData, const std::string &mergeData,
        int32_t userId) override;

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

    ErrCode GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
        std::string &othersMergePolicyData) override;
    
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override;
 
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override;

protected:
    virtual ErrCode OnSetPolicy(bool &data, bool &currentData, bool &mergePolicy, int32_t userId);

    virtual ErrCode OnAdminRemove(const std::string &adminName, bool &data, bool &mergeData, int32_t userId);

    virtual ErrCode SetOtherModulePolicy(bool data, int32_t userId);

    virtual ErrCode CheckConflictPolicy(int32_t userId);

    virtual void OnHandlePolicyDone(bool data, bool isGlobalChanged, int32_t userId);
 
    virtual void OnAdminRemoveDone(int32_t userId);

    std::string persistParam_;

    bool currentPolicyData_ = false;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_BASIC_BOOL_PLUGIN_H
