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

#include "global_proxy_plugin.h"

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"
#include "net_conn_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<GlobalProxyPlugin>());

GlobalProxyPlugin::GlobalProxyPlugin()
{
    policyCode_ = EdmInterfaceCode::GLOBAL_PROXY;
    policyName_ = "global_proxy";
    permission_ = "ohos.permission.ENTERPRISE_MANAGE_NETWORK";
    permissionType_ = IPlugin::PermissionType::SUPER_DEVICE_ADMIN;
    needSave_ = false;
}

ErrCode GlobalProxyPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    std::string &policyData, bool &isChanged, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type != FuncOperateType::SET) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    OHOS::NetManagerStandard::HttpProxy httpProxy;
    if (!OHOS::NetManagerStandard::HttpProxy::Unmarshalling(data, httpProxy)) {
        EDMLOGE("GlobalProxyPlugin::SetGlobalHttpProxy Unmarshalling proxy fail.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto netConnClient = DelayedSingleton<NetManagerStandard::NetConnClient>::GetInstance();
    int32_t ret = netConnClient->SetGlobalHttpProxy(httpProxy);
    EDMLOGI("GlobalProxyPlugin::SetGlobalHttpProxy set result = %{public}d", ret);
    return ret == ERR_OK ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode GlobalProxyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    OHOS::NetManagerStandard::HttpProxy httpProxy;
    auto netConnClient = DelayedSingleton<NetManagerStandard::NetConnClient>::GetInstance();
    int32_t ret = netConnClient->GetGlobalHttpProxy(httpProxy);
    EDMLOGI("GlobalProxyPlugin::GetGlobalHttpProxy result = %{public}d", ret);
    if (ret == ERR_OK) {
        reply.WriteInt32(ERR_OK);
        if (!httpProxy.Marshalling(reply)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        return ERR_OK;
    } else {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
}
} // namespace EDM
} // namespace OHOS
