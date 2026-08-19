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

#include "publish_form_to_desktop_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "iedm_form_manager.h"
#include "iplugin_manager.h"
#include "publish_form_to_desktop_param.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<PublishFormToDesktopPlugin>());

std::shared_ptr<IExternalManagerFactory> PublishFormToDesktopPlugin::externalManagerFactory_ =
    std::make_shared<ExternalManagerFactory>();

PublishFormToDesktopPlugin::PublishFormToDesktopPlugin()
{
    EDMLOGI("PublishFormToDesktopPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP;
    policyName_ = PolicyName::POLICY_PUBLISH_FORM_TO_DESKTOP;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_REQUEST_PUBLISH_FORM,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode PublishFormToDesktopPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("PublishFormToDesktopPlugin OnHandlePolicy");
    int32_t currentUserId = externalManagerFactory_->CreateOsAccountManager()->GetCurrentUserId();
    if (currentUserId < 0) {
        EDMLOGE("PublishFormToDesktopPlugin currentUserId invalid");
        return EdmReturnErrCode::ADD_FORM_FAILED;
    }
    PublishFormToDesktopParam param;
    if (!PublishFormToDesktopParam::UnMarshalling(data, param)) {
        EDMLOGE("PublishFormToDesktopPlugin UnMarshalling fail");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (param.bundleName.empty() || param.abilityName.empty() || param.moduleName.empty() || param.name.empty()) {
        EDMLOGE("PublishFormToDesktopPlugin publishFormToDesktopParam has empty string");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (param.dimension < static_cast<int32_t>(AppExecFwk::Constants::Dimension::DIMENSION_1_2) ||
        param.dimension > static_cast<int32_t>(AppExecFwk::Constants::Dimension::DIMENSION_3_3)) {
        EDMLOGE("PublishFormToDesktopPlugin dimension invalid");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    AAFwk::Want want;
    want.SetElementName(param.bundleName, param.abilityName);
    want.SetParam("ohos.extra.param.key.module_name", param.moduleName);
    want.SetParam("ohos.extra.param.key.form_name", param.name);
    want.SetParam("ohos.extra.param.key.form_dimension", param.dimension);
    int64_t formId = 0;
    ErrCode ret = IEdmFormManager::GetInstance()->RequestPublishFormCrossUser(want, currentUserId, formId);
    if (FAILED(ret)) {
        EDMLOGE("PublishFormToDesktopPlugin RequestPublishFormCrossUser failed %{public}d", ret);
        if (ret == ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED || ret == ERR_APPEXECFWK_FORM_INVALID_PARAM) {
            // 五元组参数错误，卡片框架找不到对应卡片
            return EdmReturnErrCode::FORM_NOT_EXIST;
        } else if (ret == ERR_APPEXECFWK_FORM_PUBLISH_NO_SPACE || ret == ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS ||
            ret == ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT || ret == ERR_APPEXECFWK_FORM_MAX_FORMS_PER_USER) {
            // 卡片数量达到上限 或 桌面无空位放置卡片
            return EdmReturnErrCode::FORM_LIMIT_REACHED;
        } else if (ret == ERR_APPEXECFWK_FORM_PUBLISH_NOT_SUPPORT) {
            // 不支持1*1尺寸卡片添加到桌面
            return EdmReturnErrCode::FORM_TYPE_NOT_SUPPORT;
        } else {
            return EdmReturnErrCode::ADD_FORM_FAILED;
        }
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(std::to_string(formId));
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
