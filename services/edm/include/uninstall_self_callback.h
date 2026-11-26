/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_UNINSTALL_SELF_CALLBACK_H
#define SERVICES_EDM_INCLUDE_UNINSTALL_SELF_CALLBACK_H

#include <atomic>
#include <future>
#include <string>

#include "status_receiver_host.h"

namespace OHOS {
namespace EDM {
class UninstallSelfCallback : public AppExecFwk::StatusReceiverHost {
public:
    UninstallSelfCallback() = default;
    ~UninstallSelfCallback() override = default;
    UninstallSelfCallback(const UninstallSelfCallback &) = delete;
    UninstallSelfCallback &operator=(const UninstallSelfCallback &) = delete;

    void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    void OnStatusNotify(const int32_t progress) override;
    bool WaitFinished(int32_t &resultCode, std::string &resultMsg);

private:
    std::atomic<bool> finished_ { false };
    std::promise<int32_t> resultCodeSignal_;
    std::promise<std::string> resultMsgSignal_;
    std::shared_future<int32_t> resultCodeFuture_ = resultCodeSignal_.get_future().share();
    std::shared_future<std::string> resultMsgFuture_ = resultMsgSignal_.get_future().share();
};
}  // namespace EDM
}  // namespace OHOS

#endif  // SERVICES_EDM_INCLUDE_UNINSTALL_SELF_CALLBACK_H
