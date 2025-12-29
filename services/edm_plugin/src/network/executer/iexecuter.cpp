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
const std::string JUMP_NFLOG_OPTION = " -j NFLOG --nflog-group 0 --nflog-prefix ";
const std::string LOG_TAG_DROP = "iptables-edm-drop:";
const std::string LOG_TAG_REJECT = "iptables-edm-reject:";
const std::string NFLOG = "NFLOG";
const std::string LOG_FLAG = "LOG flags";
const std::string IPTYPE_IPV4 = "ipv4-";
const std::string IPTYPE_IPV6 = "ipv6-";
const uint32_t RESULT_MIN_SIZE = 3;

IExecuter::IExecuter(std::string chainName) : chainName_(std::move(chainName))
{
    tableName_ = "filter";
}

ErrCode IExecuter::CreateChain(NetsysNative::IptablesType ipType)
{
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_ << NEW_OPTION << chainName_;
    std::string result;
    return ExecuterUtils::GetInstance()->Execute(oss.str(), result, ipType);
}

ErrCode IExecuter::Add(const std::shared_ptr<ChainRule>& rule, NetsysNative::IptablesType ipType, LogType logType)
{
    if (rule == nullptr) {
        EDMLOGE("Add: error param.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_;
    oss << APPEND_OPTION << chainName_;
    return ExecWithOption(oss, rule, ipType, logType);
}

ErrCode IExecuter::Remove(const std::shared_ptr<ChainRule>& rule, NetsysNative::IptablesType ipType, LogType logType)
{
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_;
    if (rule == nullptr || rule->Parameter(true).empty()) {
        oss << FLUSH_OPTION << chainName_;
    } else {
        oss << DELETE_OPTION << chainName_;
        return ExecWithOption(oss, rule, ipType, logType);
    }
    std::string result;
    return ExecuterUtils::GetInstance()->Execute(oss.str(), result, ipType);
}

ErrCode IExecuter::ExecWithOption(std::ostringstream& oss, const std::shared_ptr<ChainRule>& rule,
    NetsysNative::IptablesType ipType, LogType logType)
{
    oss << rule->Parameter();
    // for interception rules, log needs to be recorded.
    std::string rulePrefix = oss.str();
    std::string ruleTarget = rule->Target();
    std::string logRule;
    std::string nflogRule;
    std::string ipTypeStr = ipType == NetsysNative::IptablesType::IPTYPE_IPV6 ? IPTYPE_IPV6 : IPTYPE_IPV4;
    if (ruleTarget == REJECT_TARGET) {
        // no need to use the "" symbol
        oss << JUMP_LOG_OPTION << ipTypeStr << LOG_TAG_REJECT;
        logRule = oss.str();
        oss.str({});
        oss << rulePrefix << JUMP_NFLOG_OPTION << ipTypeStr << LOG_TAG_REJECT;
        nflogRule = oss.str();
    } else if (ruleTarget == DROP_TARGET) {
        // no need to use the "" symbol
        oss << JUMP_LOG_OPTION << ipTypeStr << LOG_TAG_DROP;
        logRule = oss.str();
        oss.str({});
        oss << rulePrefix << JUMP_NFLOG_OPTION << ipTypeStr << LOG_TAG_DROP;
        nflogRule = oss.str();
    } else {
        oss << JUMP_OPTION << rule->Target();
        std::string result;
        return ExecuterUtils::GetInstance()->Execute(oss.str(), result, ipType);
    }

    oss.str({});
    oss << rulePrefix << JUMP_OPTION << rule->Target();
    std::string interceptRule = oss.str();

    std::string result;
    // "-j LOG" must be before "-j REJECT"/"-j DROP"
    ErrCode ret = ExecuterUtils::GetInstance()->Execute(logRule, result, ipType);
    if (ret != ERR_OK) {
        EDMLOGE("ExecWithOption: exec interception rule log fail.");
    }
#ifdef FEATURE_PC_ONLY
    if (logType == LogType::NFLOG) {
        EDMLOGI("ExecWithOption: exec interception nflog rule = %{public}s.", nflogRule.c_str());
        ret = ExecuterUtils::GetInstance()->Execute(nflogRule, result, ipType);
        if (ret != ERR_OK) {
            EDMLOGE("ExecWithOption: exec interception rule nflog fail.");
        }
    }
#endif
    return ExecuterUtils::GetInstance()->Execute(interceptRule, result, ipType);
}

ErrCode IExecuter::GetAll(std::vector<std::string>& ruleList, NetsysNative::IptablesType ipType)
{
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_ << " -n -v -L " << chainName_ << " --line-number";
    std::string result;
    ErrCode ret = ExecuterUtils::GetInstance()->Execute(oss.str(), result, ipType);
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

    bool haveNflog = false;
    for (uint32_t i = RESULT_MIN_SIZE - 1; i < ruleLines.size(); ++i) {
        auto nflogIndex = ruleLines[i].find(NFLOG);
        if (nflogIndex != std::string ::npos) {
            EDMLOGI("GetAll: nflog string is: %{public}s", ruleLines[i].c_str());
            haveNflog = true;
        }
        // user remove rules without nflog, do not affect get next rule result
        auto logIndex = ruleLines[i].find(LOG_FLAG);
        if (logIndex != std::string ::npos) {
            haveNflog = false;
        }
        auto index = ruleLines[i].find(LOG_TAG_REJECT);
        if (index != std::string ::npos) {
            continue;
        }
        index = ruleLines[i].find(LOG_TAG_DROP);
        if (index != std::string ::npos) {
            continue;
        }
        if (haveNflog) {
            ruleLines[i] += NFLOG;
        }
        haveNflog = false;
        ruleList.emplace_back(ruleLines[i]);
    }
    return ERR_OK;
}

bool IExecuter::ChainInit(NetsysNative::IptablesType ipType)
{
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_ << " -L " << chainName_;
    std::string result;
    ErrCode ret = ExecuterUtils::GetInstance()->Execute(oss.str(), result, ipType);
    if (result.empty()) {
        EDMLOGD("IExecuter::The chain is not initialized: %{public}d, %{public}s", ret, result.c_str());
        return false;
    } else {
        EDMLOGD("IExecuter::The chain initialization has been completed: %{public}d, %{public}s", ret, result.c_str());
    }
    return true;
}

ErrCode IExecuter::ClearDefaultDenyChain(NetsysNative::IptablesType ipType)
{
    return Remove(nullptr, ipType);
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS