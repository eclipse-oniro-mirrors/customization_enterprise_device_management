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

#include "iexecuter.h"

#include <iostream>
#include <sstream>

#include "edm_log.h"
#include "executer_utils.h"
#include "rule_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const std::string NEW_OPTION = " -N ";
const std::string SELECT_TABLE_OPTION = "-t ";
const std::string INSERT_OPTION = " -I ";
const std::string APPEND_OPTION = " -A ";
const std::string DELETE_OPTION = " -D ";
const std::string FLUSH_OPTION = " -F ";
const std::string JUMP_OPTION = " -j ";
const std::string JUMP_LOG_OPTION = " -j LOG --log-prefix ";
const std::string LOG_TAG_DROP = "iptables-edm-drop:";
const std::string LOG_TAG_REJECT = "iptables-edm-reject:";
const uint32_t RESULT_MIN_SIZE = 3;

IExecuter::IExecuter(std::string chainName) : chainName_(std::move(chainName))
{
    tableName_ = "filter";
}

ErrCode IExecuter::CreateChain()
{
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_ << NEW_OPTION << chainName_;
    std::string result;
    return ExecuterUtils::GetInstance()->Execute(oss.str(), result);
}

ErrCode IExecuter::Add(const std::shared_ptr<ChainRule>& rule)
{
    if (rule == nullptr) {
        EDMLOGE("Add: error param.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_;
    oss << APPEND_OPTION << chainName_;
    return ExecWithOption(oss, rule);
}

ErrCode IExecuter::Remove(const std::shared_ptr<ChainRule>& rule)
{
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_;
    if (rule == nullptr || rule->Parameter().empty()) {
        oss << FLUSH_OPTION << chainName_;
    } else {
        oss << DELETE_OPTION << chainName_;
        return ExecWithOption(oss, rule);
    }
    std::string result;
    return ExecuterUtils::GetInstance()->Execute(oss.str(), result);
}

ErrCode IExecuter::ExecWithOption(std::ostringstream& oss, const std::shared_ptr<ChainRule>& rule)
{
    oss << rule->Parameter();
    // for interception rules, log needs to be recorded.
    std::string rulePrefix = oss.str();
    std::string ruleTarget = rule->Target();
    if (ruleTarget == REJECT_TARGET) {
        // no need to use the "" symbol
        oss << JUMP_LOG_OPTION << LOG_TAG_REJECT;
    } else if (ruleTarget == DROP_TARGET) {
        // no need to use the "" symbol
        oss << JUMP_LOG_OPTION << LOG_TAG_DROP;
    } else {
        oss << JUMP_OPTION << rule->Target();
        std::string result;
        return ExecuterUtils::GetInstance()->Execute(oss.str(), result);
    }

    std::string logRule = oss.str();

    oss.str({});
    oss << rulePrefix << JUMP_OPTION << rule->Target();
    std::string interceptRule = oss.str();

    std::string result;
    // "-j LOG" must be before "-j REJECT"/"-j DROP"
    ErrCode ret = ExecuterUtils::GetInstance()->Execute(logRule, result);
    if (ret != ERR_OK) {
        EDMLOGE("ExecWithOption: exec interception rule log fail.");
    }
    return ExecuterUtils::GetInstance()->Execute(interceptRule, result);
}

ErrCode IExecuter::GetAll(std::vector<std::string>& ruleList)
{
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_ << " -n -v -L " << chainName_ << " --line-number";
    std::string result;
    ErrCode ret = ExecuterUtils::GetInstance()->Execute(oss.str(), result);
    if (ret != ERR_OK) {
        return ret;
    }
    std::istringstream iss(result);
    std::vector<std::string> ruleLines;
    std::string line;
    while (getline(iss, line)) {
        EDMLOGD("GetAll: line: %{public}s", line.c_str());
        ruleLines.emplace_back(line);
    }
    if (ruleLines.size() < RESULT_MIN_SIZE) {
        EDMLOGI("GetAll: ruleLines is empty");
        return ERR_OK;
    }

    for (uint32_t i = RESULT_MIN_SIZE - 1; i < ruleLines.size(); ++i) {
        auto index = ruleLines[i].find(LOG_TAG_REJECT);
        if (index != std::string ::npos) {
            continue;
        }
        index = ruleLines[i].find(LOG_TAG_DROP);
        if (index != std::string ::npos) {
            continue;
        }
        ruleList.emplace_back(ruleLines[i]);
    }
    return ERR_OK;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS