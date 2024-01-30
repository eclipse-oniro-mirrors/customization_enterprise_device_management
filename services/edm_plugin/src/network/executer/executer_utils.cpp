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

#include "edm_log.h"
#include "netsys_controller.h"

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
    EDMLOGD("ExecuterUtils Execute:%{public}s", rule.c_str());
    ErrCode ret = NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(rule, result);
    if (ret != ERR_OK) {
        if (!result.empty()) {
            EDMLOGE("ExecuterUtils Execute fail:%{public}d, %{public}s", ret, result.c_str());
        } else {
            EDMLOGE("ExecuterUtils Execute fail:%{public}d", ret);
        }
        return ret;
    }
    return ERR_OK;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS