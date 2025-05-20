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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "installed_bundle_info_list_query.h"
#undef protected
#undef private

#include "utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
class InstalledBundleInfoListQueryTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;
};

void InstalledBundleInfoListQueryTest::SetUp() {
    Utils::SetEdmInitialEnv();
}

void InstalledBundleInfoListQueryTest::TearDown() {
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: InstalledBundleInfoListQueryBasicInfo
 * @tc.desc: Test InstalledBundleInfoListQuery basic info check
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, InstalledBundleInfoListQueryBasicInfo, TestSize.Level1)
{
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    std::string permissionTag;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_INSTALLED_BUNDLE_INFO_LIST);
}

/**
 * @tc.name: TestInstalledBundleInfoListQuery
 * @tc.desc: Test InstalledBundleInfoListQuery::QueryPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestQueryPolicy, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    std::string policyValue{"InstalledBundleInfoListQuery"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestConvertBundleInfoList
 * @tc.desc: Test InstalledBundleInfoListQuery::ConvertBundleInfoList func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestConvertBundleInfoList, TestSize.Level1)
{
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundlename";
    OHOS::AppExecFwk::ApplicationInfo appInfo;
    appInfo.iconPath = "$media:app_icon";
    bundleInfo.applicationInfo = appInfo;
    
    OHOS::EDM::EdmBundleInfo edmBundleInfo;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertBundleInfoList(bundleInfo, edmBundleInfo);
    ASSERT_TRUE(bundleInfo.name == edmBundleInfo.name);
    ASSERT_TRUE(bundleInfo.applicationInfo.iconPath == edmBundleInfo.applicationInfo.icon);
}

/**
 * @tc.name: TestConvertApplicationInfo
 * @tc.desc: Test InstalledBundleInfoListQuery::ConvertApplicationInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestConvertApplicationInfo, TestSize.Level1)
{
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundlename";
    OHOS::AppExecFwk::ApplicationInfo appInfo;
    appInfo.iconPath = "$media:app_icon";
    appInfo.isSystemApp = true;
    bundleInfo.applicationInfo = appInfo;
    
    OHOS::EDM::EdmApplicationInfo edmApplicationInfo;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertApplicationInfo(bundleInfo.applicationInfo, edmApplicationInfo);
    ASSERT_TRUE(bundleInfo.applicationInfo.iconPath == edmApplicationInfo.icon);
    ASSERT_TRUE(bundleInfo.applicationInfo.isSystemApp == edmApplicationInfo.isSystemApp);
}

/**
 * @tc.name: TestConvertSignatureInfo
 * @tc.desc: Test InstalledBundleInfoListQuery::ConvertSignatureInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestConvertSignatureInfo, TestSize.Level1)
{
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundlename";
    OHOS::AppExecFwk::SignatureInfo signatureInfo;
    signatureInfo.appId = "appId";
    signatureInfo.fingerprint = "fingerprint";
    signatureInfo.appIdentifier = "appIdentifier";
    signatureInfo.certificate = "certificate";
    bundleInfo.signatureInfo = signatureInfo;
    
    EdmSignatureInfo edmSignatureInfo;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertSignatureInfo(bundleInfo.signatureInfo, edmSignatureInfo);
    ASSERT_TRUE(bundleInfo.signatureInfo.appId == edmSignatureInfo.appId);
    ASSERT_TRUE(bundleInfo.signatureInfo.fingerprint == edmSignatureInfo.fingerprint);
    ASSERT_TRUE(bundleInfo.signatureInfo.appIdentifier == edmSignatureInfo.appIdentifier);
    ASSERT_TRUE(bundleInfo.signatureInfo.certificate == edmSignatureInfo.certificate);
}

/**
 * @tc.name: TestConvertResourceInfo
 * @tc.desc: Test InstalledBundleInfoListQuery::ConvertResourceInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestConvertResourceInfo, TestSize.Level1)
{
    OHOS::AppExecFwk::Resource resource;
    resource.id = 123;
    resource.bundleName = "bundleName";
    resource.moduleName = "moduleName";
    
    EdmResource edmResource;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertResourceInfo(resource, edmResource);
    ASSERT_TRUE(resource.id == edmResource.id);
    ASSERT_TRUE(resource.bundleName == edmResource.bundleName);
    ASSERT_TRUE(resource.moduleName == edmResource.moduleName);
}

/**
 * @tc.name: TestWriteVectorToParcelIntelligent
 * @tc.desc: Test InstalledBundleInfoListQuery::WriteVectorToParcelIntelligent func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestWriteVectorToParcelIntelligent, TestSize.Level1)
{
    EdmBundleInfo edmBundleInfo;
    edmBundleInfo.name = "name";
    std::vector<EdmBundleInfo> edmBundleInfos;
    edmBundleInfos.emplace_back(edmBundleInfo);
    
    MessageParcel reply;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    bool ret = queryObj->WriteVectorToParcelIntelligent(edmBundleInfos, reply);
    ASSERT_TRUE(ret);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    int32_t size = 0;
    ASSERT_TRUE(reply.ReadInt32(size) && (size != 0));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
