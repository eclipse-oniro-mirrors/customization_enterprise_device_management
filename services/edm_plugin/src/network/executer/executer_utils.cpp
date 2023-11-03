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

#include "executer_utils.h"

#include <iostream>

namespace OHOS {
namespace EDM {
namespace IPTABLES {

std::shared_ptr<ExecuterUtils> ExecuterUtils::instance_ = nullptr;
std::mutex ExecuterUtils::mutexLock_;
std::shared_ptr<ExecuterUtils> ExecuterUtils::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<ExecuterUtils> temp = std::make_shared<ExecuterUtils>();
            instance_ = temp;
        }
    }
    return instance_;
}

ErrCode ExecuterUtils::Execute(const std::string& rule, std::string &result)
{
    std::cout << "Execute=> iptables" << rule << std::endl;
    return ERR_OK;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS