/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_INSTALL_ENTERPRISE_RE_SIGNATURE_CERTIFICATE_H
#define SERVICES_EDM_PLUGIN_INCLUDE_INSTALL_ENTERPRISE_RE_SIGNATURE_CERTIFICATE_H

#include <message_parcel.h>

#include "bundle_mgr_interface.h"
#include "iplugin.h"

namespace OHOS {
namespace EDM {
class InstallEnterpriseReSignatureCertificatePlugin : public IPlugin {
public:
    InstallEnterpriseReSignatureCertificatePlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override {};
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override
        {return ERR_OK;};
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
        const std::string &mergeJsonData, int32_t userId) override {return ERR_OK;};
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override {};
    void OnOtherServiceStart(int32_t systemAbilityId) override {};
    ErrCode GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
        std::string &othersMergePolicyData) override {return ERR_OK;};

private:
    static ErrCode InstallEnterpriseReSignatureCertificate(MessageParcel &data);
    static ErrCode UninstallEnterpriseReSignatureCertificate(MessageParcel &data);
    static ErrCode CheckParamVaild(std::string certificateAlias, int32_t fd, int32_t accountId);
    static sptr<AppExecFwk::IBundleMgr> GetIBundleManager();
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_INSTALL_ENTERPRISE_RE_SIGNATURE_CERTIFICATE_H
