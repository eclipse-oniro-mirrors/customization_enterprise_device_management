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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_EXECUTER_FACTORY_H
#define SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_EXECUTER_FACTORY_H

#include <unistd.h>

#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "iexecuter.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

class ExecuterFactory {
public:
    std::shared_ptr<IExecuter> GetExecuter(const std::string &chainName) const;

    std::vector<std::shared_ptr<IExecuter>> GetAllExecuter() const;

    static std::shared_ptr<ExecuterFactory> GetInstance();
private:
    static std::shared_ptr<ExecuterFactory> instance_;
    static std::mutex mutexLock_;

    std::unordered_map<std::string, std::shared_ptr<IExecuter>> executerMap_;
    std::vector<std::string> chainNames_;
    std::vector<std::shared_ptr<IExecuter>> executerVector_;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_EXECUTER_FACTORY_H
