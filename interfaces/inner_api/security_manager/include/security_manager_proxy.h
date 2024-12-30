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

#ifndef INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_SECURITY_MANAGER_PROXY_H
#define INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_SECURITY_MANAGER_PROXY_H

#include "clipboard_policy.h"
#include "enterprise_device_mgr_proxy.h"
#include "password_policy.h"
#include "pixel_map.h"

namespace OHOS {
namespace EDM {
struct DeviceEncryptionStatus {
    bool isEncrypted = false;
};

struct CertBlobCA {
    std::vector<uint8_t> certArray;
    std::string alias;
    int32_t accountId = 0;
};

class SecurityManagerProxy {
public:
    static std::shared_ptr<SecurityManagerProxy> GetSecurityManagerProxy();
    int32_t GetSecurityPatchTag(const AppExecFwk::ElementName &admin, std::string &info);
    int32_t GetSecurityPatchTag(MessageParcel &data, std::string &info);
    int32_t GetDeviceEncryptionStatus(const AppExecFwk::ElementName &admin,
        DeviceEncryptionStatus &deviceEncryptionStatus);
    int32_t GetDeviceEncryptionStatus(MessageParcel &data, DeviceEncryptionStatus &deviceEncryptionStatus);
    int32_t SetPasswordPolicy(MessageParcel &data);
    int32_t GetPasswordPolicy(const AppExecFwk::ElementName &admin, PasswordPolicy &policy);
    int32_t GetPasswordPolicy(PasswordPolicy &policy);
    int32_t GetRootCheckStatus(const AppExecFwk::ElementName &admin, std::string &info);
    int32_t SetAppClipboardPolicy(MessageParcel &data);
    int32_t GetAppClipboardPolicy(const AppExecFwk::ElementName &admin, const int32_t tokenId,
        std::string &policy);
    int32_t SetWatermarkImage(const AppExecFwk::ElementName &admin, const std::string &bundleName,
        const std::shared_ptr<Media::PixelMap> pixelMap, const int32_t accountId);
    int32_t CancelWatermarkImage(MessageParcel &data);
    int32_t InstallUserCertificate(const AppExecFwk::ElementName &admin,
        const CertBlobCA &certblobCA, std::string &result, std::string &innerCodeMsg);
    int32_t GetUserCertificates(MessageParcel &data, std::vector<std::string> &uriList);
private:
    int32_t GetPasswordPolicy(const AppExecFwk::ElementName *admin, PasswordPolicy &policy);
    bool WritePixelMap(const std::shared_ptr<Media::PixelMap> pixelMap, MessageParcel &data);
    static std::shared_ptr<SecurityManagerProxy> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_SECURITY_MANAGER_PROXY_H