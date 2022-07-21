/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EDM_IPLUGIN_H
#define SERVICES_EDM_INCLUDE_EDM_IPLUGIN_H

#include <iostream>
#include <map>
#include <string>
#include "edm_errors.h"
#include "func_code_utils.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
class IPlugin {
public:
    /*
     * handle policy
     *
     * @param funcCode func code
     * @param data Data sent from the DPC
     * @param policyData Policy data after processing
     * @param isChanged Whether the data is changed
     * @return If the operation is successful, ERR_OK is returned.
     */
    virtual ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, std::string &policyData,
        bool &isChanged) = 0;

    /*
     * Merge policy data
     *
     * @param adminName current admin name
     * @param policyData in:Current cached policy data,out:comprehensive data of all admins currently cached.
     * @return If ERR_OK is returned,policyData incoming and outgoing data will be saved to a file.
     */
    virtual ErrCode MergePolicyData(const std::string &adminName, std::string &policyData);
    virtual void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged) = 0;
    virtual ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData) = 0;
    virtual void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData) = 0;
    virtual ErrCode WritePolicyToParcel(const std::string &policyData, MessageParcel &reply);
    std::uint32_t GetCode();
    std::string GetPolicyName();
    bool NeedSavePolicy();
    bool IsGlobalPolicy();
    std::string GetPermission();
    virtual ~IPlugin();

protected:
    std::uint32_t policyCode_;
    std::string policyName_;
    std::string permission_;
    bool needSave_ = true;
    bool isGlobal_ = true;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_IPLUGIN_H
