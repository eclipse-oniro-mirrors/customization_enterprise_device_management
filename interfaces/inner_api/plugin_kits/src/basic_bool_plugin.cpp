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

#include "basic_bool_plugin.h"

#include "parameters.h"

#include "bool_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
ErrCode BasicBoolPlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergePolicy, int32_t userId)
{
    EDMLOGE("BasicBoolPlugin %{public}d, %{public}d, %{public}d.", data, currentData, mergePolicy);
    if (mergePolicy) {
        currentData = data;
        return ERR_OK;
    }
    ErrCode ret = SetOtherModulePolicy(data, userId);
    if (FAILED(ret)) {
        return ret;
    }
    if (!persistParam_.empty() && !system::SetParameter(persistParam_, data ? "true" : "false")) {
        EDMLOGE("BasicBoolPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergePolicy = data;
    return ERR_OK;
}

ErrCode BasicBoolPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    return ERR_OK;
}

ErrCode BasicBoolPlugin::OnAdminRemove(const std::string &adminName, bool &data, bool &mergeData, int32_t userId)
{
    EDMLOGI("BasicBoolPlugin OnAdminRemove adminName : %{public}s, data : %{public}d", adminName.c_str(), data);
    if (!mergeData && data) {
        ErrCode ret = RemoveOtherModulePolicy(userId);
        if (FAILED(ret)) {
            return ret;
        }
        if (!persistParam_.empty() && !system::SetParameter(persistParam_, "false")) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode BasicBoolPlugin::RemoveOtherModulePolicy(int32_t userId)
{
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
