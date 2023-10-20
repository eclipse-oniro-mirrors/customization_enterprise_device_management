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

#include "set_browser_policies_plugin.h"

#include "bundle_manager_utils.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "map_string_serializer.h"
#include "want.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetBrowserPoliciesPlugin::GetPlugin());
const char* const BROWSER_POLICY_CHANGED_EVENT = "com.ohos.edm.browserpolicychanged";

void SetBrowserPoliciesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<SetBrowserPoliciesPlugin, std::map<std::string, std::string>>> ptr)
{
    EDMLOGD("SetBrowserPoliciesPlugin InitPlugin.");
    ptr->InitAttribute(EdmInterfaceCode::SET_BROWSER_POLICIES, "set_browser_policies", true);
    ptr->InitPermission(FuncOperateType::SET, "ohos.permission.ENTERPRISE_SET_BROWSER_POLICY",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ptr->SetSerializer(MapStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetBrowserPoliciesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyDoneListener(&SetBrowserPoliciesPlugin::OnSetPolicyDone, FuncOperateType::SET);
}

ErrCode SetBrowserPoliciesPlugin::OnSetPolicy(std::map<std::string, std::string> &policies,
    std::map<std::string, std::string> &currentData, int32_t userId)
{
    EDMLOGD("SetBrowserPoliciesPlugin OnSetPolicy.");
    if (policies.empty()) {
        EDMLOGD("SetBrowserPoliciesPlugin policies is empty.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto iter = policies.begin();
    if (iter->second.empty()) {
        currentData.erase(iter->first);
    } else {
        currentData[iter->first] = iter->second;
    }
    return ERR_OK;
}

void SetBrowserPoliciesPlugin::OnSetPolicyDone(bool isGlobalChanged)
{
    if (!isGlobalChanged) {
        return;
    }
    NotifyBrowserPolicyChanged();
}

ErrCode SetBrowserPoliciesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::map<std::string, std::string> policies;
    pluginInstance_->serializer_->Deserialize(policyData, policies);
    std::string appId = data.ReadString();
    if (appId.empty() && FAILED(BundleManagerUtils::GetAppIdByCallingUid(appId))) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    std::string policy;
    if (policies.count(appId) > 0) {
        policy = policies[appId];
    }
    reply.WriteString(policy);
    return ERR_OK;
}

void SetBrowserPoliciesPlugin::NotifyBrowserPolicyChanged()
{
    EDMLOGD("SetBrowserPoliciesPlugin NotifyBrowserPolicyChanged.");
    AAFwk::Want want;
    want.SetAction(BROWSER_POLICY_CHANGED_EVENT);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData)) {
        EDMLOGE("NotifyBrowserPolicyChanged failed.");
    }
}
} // namespace EDM
} // namespace OHOS
