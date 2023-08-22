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

#ifndef INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_BUNDLE_MANAGER_PROXY_H
#define INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_BUNDLE_MANAGER_PROXY_H
#include "enterprise_device_mgr_proxy.h"
#include "install_param.h"

namespace OHOS {
namespace EDM {
class BundleManagerProxy {
public:
    BundleManagerProxy();
    ~BundleManagerProxy();
    static std::shared_ptr<BundleManagerProxy> GetBundleManagerProxy();
    int32_t AddBundlesByPolicyType(AppExecFwk::ElementName &admin, std::vector<std::string> &bundles, int32_t userId,
        int32_t policyType);
    int32_t RemoveBundlesByPolicyType(AppExecFwk::ElementName &admin, std::vector<std::string> &bundles, int32_t userId,
        int32_t policyType);
    int32_t GetBundlesByPolicyType(AppExecFwk::ElementName &admin, int32_t userId, std::vector<std::string> &bundles,
        int32_t policyType);
    int32_t Uninstall(AppExecFwk::ElementName &admin, std::string bundleName, int32_t userId, bool isKeepData,
        std::string &retMessage);
    int32_t Install(AppExecFwk::ElementName &admin, std::vector<std::string> &hapFilePaths,
        AppExecFwk::InstallParam &installParam, std::string &retMessage);

private:
    void AddPolicyTypeMap();
    static std::shared_ptr<BundleManagerProxy> instance_;
    static std::mutex mutexLock_;
    std::map<int32_t, uint32_t> policyTypeMap_;
    ErrCode WriteFileToInner(MessageParcel &reply, const std::string &realPath, std::vector<std::string> &servicePaths,
        std::string &errMessage);
    ErrCode WriteFileToStream(AppExecFwk::ElementName &admin, const std::string &path,
        std::vector<std::string> &servicePaths, std::string &errMessage);
    ErrCode checkHapFilePath(const std::string &hapFilePath, std::string &fileName, std::string &realPath,
        std::string &errMessage);
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_BUNDLE_MANAGER_PROXY_H