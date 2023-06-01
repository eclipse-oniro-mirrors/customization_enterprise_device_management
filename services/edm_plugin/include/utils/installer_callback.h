/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef EDM_INSTALLER_CALLBACK_H
#define EDM_INSTALLER_CALLBACK_H

#include <future>

#include "nocopyable.h"
#include "status_receiver_host.h"

namespace OHOS {
namespace EDM {
class InstallerCallback : public OHOS::AppExecFwk::StatusReceiverHost {
public:
    InstallerCallback() = default;
    ~InstallerCallback() override = default;
    void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    void OnStatusNotify(const int32_t progress) override;
    int32_t GetResultCode();
    std::string GetResultMsg();

private:
    std::promise<int32_t> resultCodeSignal_;
    std::promise<std::string> resultMsgSignal_;
    DISALLOW_COPY_AND_MOVE(InstallerCallback);
};
}  // namespace EDM
}  // namespace OHOS
#endif  // EDM_INSTALLER_CALLBACK_H