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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPTABLES_FACTORY_H
#define SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPTABLES_FACTORY_H

#include <memory>
#include "iptables_utils.h"
#include "ipv4tables_manager.h"
#include "ipv6tables_manager.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

class IptablesFactory {
public:
    static std::shared_ptr<IptablesFactory> GetInstance();
    std::shared_ptr<IptablesManager> CreateIptablesManagerForFamily(Family family);

private:
    std::shared_ptr<IptablesManager> ipv4tablesManager_ = std::make_shared<Ipv4tablesManager>();
    std::shared_ptr<IptablesManager> ipv6tablesManager_ = std::make_shared<Ipv6tablesManager>();
    static std::shared_ptr<IptablesFactory> instance_;
    static std::mutex mutexLock_;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPTABLES_FACTORY_H
