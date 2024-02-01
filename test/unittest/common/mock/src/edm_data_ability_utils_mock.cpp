/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

const std::string KEY_POWER_SUSPEND = "settings.power.suspend_sources";
std::string EdmDataAbilityUtils::result_;
void EdmDataAbilityUtils::SetResult(const std::string &result)
{
    result_ = result;
}

ErrCode EdmDataAbilityUtils::GetStringFromSettingsDataShare(const std::string &key, std::string &value)
{
    GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils GetStringFromDataShare start: " << result_.c_str();
    if (result_ == "test Failed") {
        GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils test Failed";
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    } else if (result_ == "test value nullptr") {
        GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils test nullptr";
        return ERR_OK;
    } else if (result_ == "power_suspend_normal") {
        value =
            "{\"lid\":{\"action\":1,\"delayMs\":0},\"powerkey\":{\"action\":1,\"delayMs\":0},\"switch\":{\"action\":1,"
            "\"delayMs\":0},\"timeout\":{\"action\":1,\"delayMs\":0}}";
        return ERR_OK;
    } else if (result_ == "power_suspend_json_error") {
        value = "json error";
        return ERR_OK;
    } else if (result_ == "power_suspend_json_no_time_out") {
        value =
            "{\"lid\":{\"action\":1,\"delayMs\":0},\"powerkey\":{\"action\":1,\"delayMs\":0},\"switch\":{\"action\":1,"
            "\"delayMs\":0},\"timeerror\":{\"action\":1,\"delayMs\":0}}";
        return ERR_OK;
    } else if (result_ == "power_suspend_json_key_not_object") {
        value =
            "{\"lid\":{\"action\":1,\"delayMs\":0},\"powerkey\":{\"action\":1,\"delayMs\":0},\"switch\":{\"action\":1,"
            "\"delayMs\":0},\"timeout\":1000}";
        return ERR_OK;
    }
    GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils test Success";
    value = "test query success";
    return ERR_OK;
}

ErrCode EdmDataAbilityUtils::GetIntFromSettingsDataShare(const std::string &key, int32_t &value)
{
    GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils GetIntFromDataShare start: " << result_.c_str();
    if (result_ == "SYSTEM_ABNORMALLY") {
        GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils result SYSTEM_ABNORMALLY";
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    GTEST_LOG_(INFO) << "mock EdmDataAbilityUtils test Success";
    value = 0;
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS