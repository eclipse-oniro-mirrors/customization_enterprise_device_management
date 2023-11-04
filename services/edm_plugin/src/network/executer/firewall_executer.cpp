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
#include "firewall_executer.h"

#include <sstream>
#include <utility>

#include "edm_log.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const std::string SELECT_TABLE_OPTION = "-t ";
const std::string JUMP_OPTION = " -j ";
const std::string INSERT_OPTION = " -I ";

FirewallExecuter::FirewallExecuter(std::string actualChainName, const std::string& chainName) : IExecuter(chainName),
    actualChainName_(std::move(actualChainName))
{
}

ErrCode FirewallExecuter::Init()
{
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_ << INSERT_OPTION << actualChainName_ << JUMP_OPTION << chainName_;
    std::string result;
    ErrCode ret = ExecuterUtils::GetInstance()->Execute(oss.str(), result);
    if (ret != ERR_OK) {
        EDMLOGE("FirewallExecuter:Init error.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS