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
#include "http_proxy_serializer.h"
#include "net_conn_client.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(GlobalProxyPlugin::GetPlugin());

void GlobalProxyPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<GlobalProxyPlugin, NetManagerStandard::HttpProxy>> ptr)
{
    EDMLOGI("GlobalProxyPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::GLOBAL_PROXY, "global_proxy", "ohos.permission.ENTERPRISE_MANAGE_NETWORK",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(HttpProxySerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&GlobalProxyPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode GlobalProxyPlugin::OnSetPolicy(NetManagerStandard::HttpProxy &httpProxy)
{
    int32_t ret = NetManagerStandard::NetConnClient::GetInstance().SetGlobalHttpProxy(httpProxy);
    EDMLOGI("GlobalProxyPlugin::SetGlobalHttpProxy set result = %{public}d", ret);
    return ret == ERR_OK ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode GlobalProxyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    NetManagerStandard::HttpProxy httpProxy;
    int32_t ret = NetManagerStandard::NetConnClient::GetInstance().GetGlobalHttpProxy(httpProxy);
    EDMLOGI("GlobalProxyPlugin::GetGlobalHttpProxy result = %{public}d", ret);
    if (ret == ERR_OK) {
        reply.WriteInt32(ERR_OK);
        if (!httpProxy.Marshalling(reply)) {
            EDMLOGE("GlobalProxyPlugin::httpProxy Marshalling error");
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
