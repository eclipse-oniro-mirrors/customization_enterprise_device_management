/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "iptables_factory.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

std::shared_ptr<IptablesFactory> IptablesFactory::instance_ = nullptr;
std::mutex IptablesFactory::mutexLock_;

std::shared_ptr<IptablesFactory> IptablesFactory::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<IptablesFactory>();
        }
    }
    return instance_;
}

std::shared_ptr<IptablesManager> IptablesFactory::CreateIptablesManagerForFamily(Family family)
{
    if (family == Family::IPV6) {
        return ipv6tablesManager_;
    }
    return ipv4tablesManager_;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS