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

#include "plugin_policy_reader.h"

#include "edm_log.h"
#include "func_code_utils.h"
#include "policy_query_factory.h"

namespace OHOS {
namespace EDM {

std::shared_ptr<PluginPolicyReader> PluginPolicyReader::instance_ = nullptr;
std::once_flag PluginPolicyReader::flag_;

std::shared_ptr<PluginPolicyReader> PluginPolicyReader::GetInstance()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<PluginPolicyReader>();
        }
    });
    return instance_;
}

ErrCode PluginPolicyReader::GetPolicyByCode(
    std::shared_ptr<PolicyManager> policyManager, uint32_t funcCode,
    MessageParcel &data, MessageParcel &reply, int32_t userId,
    const std::string &permissionTag)
{
    FuncCodeUtils::PrintFuncCode(funcCode);
    FuncFlag flag = FuncCodeUtils::GetSystemFlag(funcCode);
    if (flag != FuncFlag::POLICY_FLAG) {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    std::uint32_t code = FuncCodeUtils::GetPolicyCode(funcCode);
    return GetPolicyByCodeInner(policyManager, code, data, reply, userId, permissionTag);
}

ErrCode PluginPolicyReader::GetPolicyByCodeInner(
    std::shared_ptr<PolicyManager> policyManager, uint32_t code,
    MessageParcel &data, MessageParcel &reply, int32_t userId,
    const std::string &permissionTag)
{
    EDMLOGI("PluginPolicyReader query policy ::code %{public}u", code);
    
    ErrCode featureCheck = PolicyQueryFactory::CheckFeatureEnabled(code);
    if (FAILED(featureCheck)) {
        EDMLOGI("PluginPolicyReader: feature not enabled for code %{public}u", code);
        return featureCheck;
    }
    
    std::shared_ptr<IPolicyQuery> obj = PolicyQueryFactory::CreateQuery(code);
    EDMLOGI("GetPolicyQuery errcode = %{public}d",
        obj ? ERR_OK : EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    
    if (obj == nullptr) {
        EDMLOGI("GetPolicyQuery obj is null, query from plugin");
        return ERR_CANNOT_FIND_QUERY_FAILED;
    }
    
    return obj->GetPolicy(policyManager, code, data, reply, userId, permissionTag);
}

ErrCode PluginPolicyReader::GetPolicyQuery(std::shared_ptr<IPolicyQuery> &obj, uint32_t code)
{
    obj = PolicyQueryFactory::CreateQuery(code);
    if (obj != nullptr) {
        return ERR_OK;
    }
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

} // namespace EDM
} // namespace OHOS