/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "reset_factory_plugin.h"
#include <message_parcel.h>
#include <system_ability_definition.h>
#include <unistd.h>
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "policy_info.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
static constexpr int64_t UPDATER_SA_INIT_TIME = 1000 * 1000;
static constexpr int64_t SLEEP_TIME = 500 * 1000;
static constexpr int32_t RETRY_TIMES = 10;
static constexpr int32_t RESET_FACTORY_CODE = 18;

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(ResetFactoryPlugin::GetPlugin());

void ResetFactoryPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<ResetFactoryPlugin, std::string>> ptr)
{
    EDMLOGD("ResetFactoryPlugin InitPlugin...");
    std::string policyName;
    POLICY_CODE_TO_NAME(RESET_FACTORY, policyName);
    ptr->InitAttribute(RESET_FACTORY, policyName, "ohos.permission.ENTERPRISE_RESET_DEVICE", false);
    ptr->SetSerializer(StringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ResetFactoryPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode ResetFactoryPlugin::OnSetPolicy()
{
    EDMLOGD("ResetFactoryPlugin OnSetPolicy");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObject = samgr->GetSystemAbility(UPDATE_DISTRIBUTED_SERVICE_ID);
    if (remoteObject == nullptr) {
        if (TryLoadUpdaterSa()) {
            EDMLOGE("TryLoadUpdaterSa failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        remoteObject = samgr->GetSystemAbility(UPDATE_DISTRIBUTED_SERVICE_ID);
        if (remoteObject == nullptr) {
            EDMLOGE("remoteObject == nullptr after load update sa");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    MessageParcel parcel;
    parcel.WriteInterfaceToken(u"OHOS.Updater.IUpdateService");
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ERR_OK;
    ret = remoteObject->SendRequest(RESET_FACTORY_CODE, parcel, reply, option);
    if (FAILED(ret)) {
        EDMLOGE("ResetFactoryPlugin:OnSetPolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

void ResetFactoryPlugin::InitStatus()
{
    if (loadUpdaterSaStatus_ != LoadUpdaterSaStatus::WAIT_RESULT) {
        loadUpdaterSaStatus_ = LoadUpdaterSaStatus::WAIT_RESULT;
    }
}

bool ResetFactoryPlugin::TryLoadUpdaterSa()
{
    InitStatus();
    return LoadUpdaterSa();
}

void ResetFactoryPlugin::OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject>& remoteObject)
{
    EDMLOGI("OnLoadSystemAbilitySuccess systemAbilityId: %{public}d, IRemoteObject result: %{public}s",
        systemAbilityId, (remoteObject != nullptr) ? "succeed" : "failed");
    loadUpdaterSaStatus_ = (remoteObject != nullptr) ? LoadUpdaterSaStatus::SUCCESS : LoadUpdaterSaStatus::FAIL;
}

void ResetFactoryPlugin::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    EDMLOGE("OnLoadSystemAbilityFail systemAbilityId: %{public}d", systemAbilityId);
    loadUpdaterSaStatus_ = LoadUpdaterSaStatus::FAIL;
}

bool ResetFactoryPlugin::CheckUpdaterSaLoaded()
{
    int32_t retry = RETRY_TIMES;
    EDMLOGI("Waiting for CheckUpdaterSaLoaded");
    while (retry--)
    {
        usleep(SLEEP_TIME);
        LoadUpdaterSaStatus loadUpdaterSaStatus = loadUpdaterSaStatus_;
        if (loadUpdaterSaStatus != LoadUpdaterSaStatus::WAIT_RESULT)
        {
            bool isUpdaterSaLoaded = loadUpdaterSaStatus == LoadUpdaterSaStatus::SUCCESS;
            EDMLOGI("found OnLoad result: %{public}s", isUpdaterSaLoaded ? "succeed" : "failed");
            return isUpdaterSaLoaded;
        }
    }
    EDMLOGE("CheckUpdaterSaLoaded didn't get OnLoad result");
    return false;
}

void ResetFactoryPlugin::WaitUpdaterSaInit()
{
    usleep(UPDATER_SA_INIT_TIME);
}

bool ResetFactoryPlugin::LoadUpdaterSa()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr)
    {
        EDMLOGE("GetSystemAbilityManager samgr object null!");
        return false;
    }
    int32_t result = samgr->LoadSystemAbility(UPDATE_DISTRIBUTED_SERVICE_ID, this);
    if (result != ERR_OK)
    {
        EDMLOGE("systemAbilityId: %{public}d, load failed, result code: %{public}d", UPDATE_DISTRIBUTED_SERVICE_ID,
                result);
        return false;
    }
    if (!CheckUpdaterSaLoaded())
    {
        EDMLOGE("systemAbilityId: %{public}d, CheckUpdaterSaLoaded failed", UPDATE_DISTRIBUTED_SERVICE_ID);
        return false;
    }
    WaitUpdaterSaInit();
    EDMLOGI("systemAbilityId: %{public}d, load succeed", UPDATE_DISTRIBUTED_SERVICE_ID);
    return true;
}
} // namespace EDM
} // namespace OHOS
