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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IEXECUTER_H
#define SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IEXECUTER_H

#include <memory>
#include <string>
#include <vector>

#include "chain_rule.h"
#include "edm_errors.h"
#include "executer_utils.h"
#include "i_netsys_service.h"
#include "iptables_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

class IExecuter {
public:
    explicit IExecuter(std::string chainName);

    virtual ErrCode CreateChain(NetsysNative::IptablesType ipType);
    virtual ErrCode Init(NetsysNative::IptablesType ipType) = 0;
    virtual ErrCode Add(const std::shared_ptr<ChainRule> &rule, NetsysNative::IptablesType ipType);
    virtual ErrCode Remove(const std::shared_ptr<ChainRule> &rule, NetsysNative::IptablesType ipType);
    virtual ErrCode GetAll(std::vector<std::string> &ruleList, NetsysNative::IptablesType ipType);
    virtual bool ChainInit(NetsysNative::IptablesType ipType);

    virtual bool SetDefaultOutputDenyChain(Direction direction, Family family) = 0;
    virtual bool SetDefaultForwardDenyChain(Direction direction, Family family) = 0;

    ErrCode ClearDefaultDenyChain(NetsysNative::IptablesType ipType);

private:
    virtual ErrCode ExecWithOption(std::ostringstream &oss, const std::shared_ptr<ChainRule> &rule,
        NetsysNative::IptablesType ipType);

protected:
    IExecuter() = default;

protected:
    std::string tableName_;
    std::string chainName_;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IEXECUTER_H
