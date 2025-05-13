/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "watermark_application_observer.h"

#include "managed_event.h"
#include "os_account_manager.h"
#include "window_manager.h"
#include "wm_common.h"

namespace OHOS {
namespace EDM {
void WatermarkApplicationObserver::OnProcessCreated(const AppExecFwk::ProcessData &processData)
{
    int32_t accountId = -1;
    ErrCode ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(processData.uid, accountId);
    if (ret != ERR_OK) {
        EDMLOGE("OnProcessCreated GetOsAccountLocalIdFromUid error");
        return;
    }
    SetProcessWatermarkOnAppStart(processData.bundleName, accountId, processData.pid, true);
}

void WatermarkApplicationObserver::SetProcessWatermarkOnAppStart(const std::string &bundleName, int32_t accountId,
    int32_t pid, bool enabled)
{
    if (bundleName.empty() || accountId <= 0 || pid <= 0) {
        return;
    }

    std::string policyData;
    auto policyManager = IPolicyManager::GetInstance();
    policyManager->GetPolicy("", PolicyName::POLICY_WATERMARK_IMAGE_POLICY, policyData, EdmConstants::DEFAULT_USER_ID);

    std::map<std::pair<std::string, int32_t>, WatermarkImageType> currentData;
    auto serializer = WatermarkImageSerializer::GetInstance();
    serializer->Deserialize(policyData, currentData);
    auto iter = currentData.find(std::pair<std::string, int32_t>{bundleName, accountId});
    if (iter == currentData.end() || iter->second.fileName.empty()) {
        return;
    }
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().SetProcessWatermark(pid, iter->second.fileName, enabled);
    if (ret != Rosen::WMError::WM_OK) {
        EDMLOGE("SetAllWatermarkImage SetProcessWatermarkOnAppStart error");
    }
}
} // namespace EDM
} // namespace OHOS