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

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "plugin_manager.h"
#include "policy_manager.h"
#include "managed_event.h"
#include "os_account_manager.h"

namespace OHOS {
namespace EDM {
constexpr int32_t RETRY_SECONDS = 5;

void WatermarkApplicationObserver::OnProcessCreated(const AppExecFwk::ProcessData &processData)
{
    HandleWatermark(processData, true);
}

void WatermarkApplicationObserver::OnProcessDied(const AppExecFwk::ProcessData &processData)
{
    HandleWatermark(processData, false);
}

void WatermarkApplicationObserver::HandleWatermark(const AppExecFwk::ProcessData &processData, bool enabled)
{
    int32_t accountId = -1;
    ErrCode ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(processData.uid, accountId);
    if (ret != ERR_OK) {
        EDMLOGE("OnProcessCreated GetOsAccountLocalIdFromUid error");
        return;
    }
    SetProcessWatermarkOnAppStart(processData.bundleName, accountId, processData.pid, enabled);
}

void WatermarkApplicationObserver::SetProcessWatermarkOnAppStart(const std::string &bundleName, int32_t accountId,
    int32_t pid, bool enabled)
{
    if (bundleName.empty() || accountId <= 0 || pid <= 0) {
        return;
    }

    std::string fileName = GetWatermarkFileName(bundleName, accountId);
    if (fileName.empty()) {
        return;
    }

    EDMLOGI("SetProcessWatermarkOnAppStart bundleName %{public}s, pid %{public}d, enabled %{public}d",
        bundleName.c_str(), pid, enabled);

    auto plugin = GetWatermarkPlugin();
    if (plugin == nullptr) {
        EDMLOGE("Get watermark plugin failed");
        return;
    }

    WatermarkCallParam param;
    param.plugin = plugin;
    param.funcCode = GetWatermarkFuncCode();
    param.pid = pid;
    param.enabled = enabled;
    param.fileName = fileName;
    param.policyData = GetWatermarkPolicyData();
    param.needRetry = true;
    CallPluginSetWatermark(param);
}

std::string WatermarkApplicationObserver::GetWatermarkFileName(const std::string &bundleName, int32_t accountId)
{
    std::string policyData = GetWatermarkPolicyData();
    std::map<std::pair<std::string, int32_t>, WatermarkImageType> currentData;
    auto serializer = WatermarkImageSerializer::GetInstance();
    serializer->Deserialize(policyData, currentData);
    auto iter = currentData.find(std::pair<std::string, int32_t>{bundleName, accountId});
    if (iter == currentData.end() || iter->second.fileName.empty()) {
        return "";
    }
    return iter->second.fileName;
}

std::string WatermarkApplicationObserver::GetWatermarkPolicyData()
{
    std::string policyData;
    auto policyManager = PolicyManager::GetInstance();
    policyManager->GetPolicy("", PolicyName::POLICY_WATERMARK_IMAGE_POLICY, policyData, EdmConstants::DEFAULT_USER_ID);
    return policyData;
}

std::shared_ptr<IPlugin> WatermarkApplicationObserver::GetWatermarkPlugin()
{
    auto pluginManager = PluginManager::GetInstance();
    uint32_t funcCode = GetWatermarkFuncCode();
    return pluginManager->GetPluginByFuncCode(funcCode);
}

uint32_t WatermarkApplicationObserver::GetWatermarkFuncCode()
{
    return POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET), EdmInterfaceCode::WATERMARK_IMAGE);
}

void WatermarkApplicationObserver::CallPluginSetWatermark(const WatermarkCallParam &param)
{
    MessageParcel data;
    data.WriteString(EdmConstants::SecurityManager::SET_PROCESS_WATERMARK_BY_PID);
    data.WriteInt32(param.pid);
    data.WriteBool(param.enabled);
    data.WriteString(param.fileName);

    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    handlePolicyData.policyData = param.policyData;
    handlePolicyData.mergePolicyData = "";

    ErrCode result = param.plugin->OnHandlePolicy(param.funcCode, data, reply,
        handlePolicyData, EdmConstants::DEFAULT_USER_ID);
    if (FAILED(result) && param.needRetry) {
        ScheduleRetry(param);
    }
}

void WatermarkApplicationObserver::ScheduleRetry(const WatermarkCallParam &param)
{
    EDMLOGE("SetProcessWatermarkOnAppStart via plugin failed, will retry once");
    WatermarkCallParam retryParam = param;
    retryParam.needRetry = false;
    wptr<WatermarkApplicationObserver> weakThis(this);
    std::thread retryTask([weakThis, retryParam]() {
        std::condition_variable cv;
        std::mutex mutex;
        auto nextRun = std::chrono::steady_clock::now() + std::chrono::seconds(RETRY_SECONDS);
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait_until(lock, nextRun);
        sptr<WatermarkApplicationObserver> strongThis = weakThis.promote();
        if (strongThis != nullptr) {
            EDMLOGI("SetProcessWatermarkOnAppStart retry start, pid %{public}d", retryParam.pid);
            strongThis->CallPluginSetWatermark(retryParam);
        } else {
            EDMLOGI("WatermarkApplicationObserver destroyed, skip retry");
        }
    });
    retryTask.detach();
}
} // namespace EDM
} // namespace OHOS