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

#include "edm_data_ability_utils_mock.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string EdmDataAbilityUtils::result_;
void EdmDataAbilityUtils::SetResult(const std::string &result)
{
    result_ = result;
}

ErrCode EdmDataAbilityUtils::GetStringFromDataShare(const std::string &dataBaseUri,
    const std::string &key, std::string &value)
{
    GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils GetStringFromDataShare start: " << result_.c_str();
    if (result_ == "test Failed") {
        GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils test Failed";
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    } else if (result_ == "test value nullptr") {
        GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils test nullptr";
        return ERR_OK;
    }
    GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils test Success";
    value = "test query success";
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
