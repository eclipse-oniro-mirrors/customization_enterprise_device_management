/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "executer_utils_mock.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {
namespace TEST {

ErrCode PrintExecRule(const std::string &rule, std::string &result)
{
    EDMLOGI("PrintExecRule %{public}s", rule.c_str());
    return ERR_OK;
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS