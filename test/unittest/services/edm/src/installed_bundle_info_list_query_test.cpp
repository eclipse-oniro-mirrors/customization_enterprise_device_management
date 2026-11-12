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

#include <limits>
#include <memory>

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
}

void InstalledBundleInfoListQueryTest::TearDown() {
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
    data.WriteUint32(static_cast<uint32_t>(BundleInfoGetFlag::DEFAULT));
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestConvertBundleInfoListItem
 * @tc.desc: Test InstalledBundleInfoListQuery::ConvertBundleInfoListItem func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestConvertBundleInfoListItem, TestSize.Level1)
{
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundlename";
    OHOS::AppExecFwk::ApplicationInfo appInfo;
    appInfo.iconPath = "$media:app_icon";
    bundleInfo.applicationInfo = appInfo;
    
    OHOS::EDM::EdmBundleInfo edmBundleInfo;
    uint32_t edmBundleFlag = static_cast<uint32_t>(BundleInfoGetFlag::WITH_APPLICATION_INFO);
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertBundleInfoListItem(edmBundleFlag, bundleInfo, edmBundleInfo);
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
    appInfo.uid = 10001;
    appInfo.appUid = 20002;
    bundleInfo.applicationInfo = appInfo;
    
    OHOS::EDM::EdmApplicationInfo edmApplicationInfo;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertApplicationInfo(bundleInfo.applicationInfo, edmApplicationInfo);
    ASSERT_TRUE(bundleInfo.applicationInfo.iconPath == edmApplicationInfo.icon);
    ASSERT_TRUE(bundleInfo.applicationInfo.isSystemApp == edmApplicationInfo.isSystemApp);
    ASSERT_EQ(edmApplicationInfo.uid, bundleInfo.applicationInfo.uid);
    ASSERT_EQ(edmApplicationInfo.appUid, bundleInfo.applicationInfo.appUid);
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

/**
 * @tc.name: TestAssembleBundleResourceInfoNormal
 * @tc.desc: Test InstalledBundleInfoListQuery::AssembleBundleResourceInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestAssembleBundleResourceInfoNormal, TestSize.Level1)
{
    std::string commonNameA = "nameA";
    std::string commonNameB = "nameB";
    std::string commonResourceLableA = "resourceInfoLableA";
    std::string commonResourceLableB = "resourceInfoLableB";
    EdmBundleInfo edmBundleInfoA;
    edmBundleInfoA.name = commonNameA;
    edmBundleInfoA.applicationInfo.label = "";

    EdmBundleInfo edmBundleInfoB;
    edmBundleInfoB.name = commonNameB;
    edmBundleInfoB.applicationInfo.label = "";

    std::vector<EdmBundleInfo> edmBundleInfos;
    edmBundleInfos.emplace_back(edmBundleInfoA);
    edmBundleInfos.emplace_back(edmBundleInfoB);

    std::vector<OHOS::AppExecFwk::BundleResourceInfo> bundleResourceInfos;
    OHOS::AppExecFwk::BundleResourceInfo bundleResourceInfoA;
    bundleResourceInfoA.bundleName = commonNameA;
    bundleResourceInfoA.label = commonResourceLableA;
    OHOS::AppExecFwk::BundleResourceInfo bundleResourceInfoB;
    bundleResourceInfoB.bundleName = commonNameB;
    bundleResourceInfoB.label = commonResourceLableB;
    bundleResourceInfos.emplace_back(bundleResourceInfoA);
    bundleResourceInfos.emplace_back(bundleResourceInfoB);
    
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->AssembleBundleResourceInfo(edmBundleInfos, bundleResourceInfos);
    ASSERT_EQ(edmBundleInfos[0].applicationInfo.label, commonResourceLableA);
    ASSERT_EQ(edmBundleInfos[1].applicationInfo.label, commonResourceLableB);
}

/**
 * @tc.name: TestAssembleBundleResourceInfoNotMatch
 * @tc.desc: Test InstalledBundleInfoListQuery::AssembleBundleResourceInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestAssembleBundleResourceInfoNotMatch, TestSize.Level1)
{
    std::string commonNameA = "nameA";
    std::string commonNameB = "nameB";
    std::string commonResourceLableA = "resourceInfoLableA";
    std::string commonResourceLableB = "resourceInfoLableB";
    EdmBundleInfo edmBundleInfoA;
    edmBundleInfoA.name = commonNameA;
    edmBundleInfoA.applicationInfo.label = "";

    EdmBundleInfo edmBundleInfoB;
    edmBundleInfoB.name = commonNameB;
    edmBundleInfoB.applicationInfo.label = "";

    std::vector<EdmBundleInfo> edmBundleInfos;
    edmBundleInfos.emplace_back(edmBundleInfoA);
    edmBundleInfos.emplace_back(edmBundleInfoB);


    std::vector<OHOS::AppExecFwk::BundleResourceInfo> bundleResourceInfos;
    OHOS::AppExecFwk::BundleResourceInfo bundleResourceInfoA;
    bundleResourceInfoA.bundleName = "nameC";
    bundleResourceInfoA.label = commonResourceLableA;
    bundleResourceInfos.emplace_back(bundleResourceInfoA);
    
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->AssembleBundleResourceInfo(edmBundleInfos, bundleResourceInfos);
    ASSERT_EQ(edmBundleInfos[0].applicationInfo.label, "");
}

/**
 * @tc.name: TestAssembleBundleResourceInfoEmpty
 * @tc.desc: Test InstalledBundleInfoListQuery::AssembleBundleResourceInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestAssembleBundleResourceInfoEmpty, TestSize.Level1)
{
    std::vector<EdmBundleInfo> edmBundleInfos;
    std::vector<OHOS::AppExecFwk::BundleResourceInfo> bundleResourceInfos;

    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->AssembleBundleResourceInfo(edmBundleInfos, bundleResourceInfos);
    ASSERT_TRUE(edmBundleInfos.empty());
}

/**
 * @tc.name: TestAssembleBundleResourceInfoNormalWithIconData
 * @tc.desc: Test InstalledBundleInfoListQuery::AssembleBundleResourceInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestAssembleBundleResourceInfoNormalWithIconData, TestSize.Level1)
{
    std::string commonNameA = "nameA";
    std::string commonNameB = "nameB";
    std::string commonResourceLableA = "resourceInfoLableA";
    std::string commonResourceLableB = "resourceInfoLableB";
    std::string commonResourceIconDataA = "resourceInfoIconDataA";
    std::string commonResourceIconDataB = "resourceInfoIconDataB";
    EdmBundleInfo edmBundleInfoA;
    edmBundleInfoA.name = commonNameA;
    edmBundleInfoA.applicationInfo.label = "";
    edmBundleInfoA.applicationInfo.iconData = "";

    EdmBundleInfo edmBundleInfoB;
    edmBundleInfoB.name = commonNameB;
    edmBundleInfoB.applicationInfo.label = "";
    edmBundleInfoB.applicationInfo.iconData = "";

    std::vector<EdmBundleInfo> edmBundleInfos;
    edmBundleInfos.emplace_back(edmBundleInfoA);
    edmBundleInfos.emplace_back(edmBundleInfoB);

    std::vector<OHOS::AppExecFwk::BundleResourceInfo> bundleResourceInfos;
    OHOS::AppExecFwk::BundleResourceInfo bundleResourceInfoA;
    bundleResourceInfoA.bundleName = commonNameA;
    bundleResourceInfoA.label = commonResourceLableA;
    bundleResourceInfoA.icon = commonResourceIconDataA;
    OHOS::AppExecFwk::BundleResourceInfo bundleResourceInfoB;
    bundleResourceInfoB.bundleName = commonNameB;
    bundleResourceInfoB.label = commonResourceLableB;
    bundleResourceInfoB.icon = commonResourceIconDataB;
    bundleResourceInfos.emplace_back(bundleResourceInfoA);
    bundleResourceInfos.emplace_back(bundleResourceInfoB);
    
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->AssembleBundleResourceInfo(edmBundleInfos, bundleResourceInfos);
    ASSERT_EQ(edmBundleInfos[0].applicationInfo.label, commonResourceLableA);
    ASSERT_EQ(edmBundleInfos[1].applicationInfo.label, commonResourceLableB);
    ASSERT_EQ(edmBundleInfos[0].applicationInfo.iconData, commonResourceIconDataA);
    ASSERT_EQ(edmBundleInfos[1].applicationInfo.iconData, commonResourceIconDataB);
}

/**
 * @tc.name: TestConvertBundleInfoListData
 * @tc.desc: Test InstalledBundleInfoListQuery::TestConvertBundleInfoListData func.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, TestConvertBundleInfoListData, TestSize.Level1)
{
    std::vector<OHOS::AppExecFwk::BundleInfo> bundleInfos;
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.name = "bundleName";
    bundleInfos.emplace_back(bundleInfo);

    std::vector<EdmBundleInfo> edmBundleInfos;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertBundleInfoListData(0, bundleInfos, edmBundleInfos);
    ASSERT_EQ(bundleInfos.size(), edmBundleInfos.size());
    ASSERT_EQ(bundleInfos[0].name, edmBundleInfos[0].name);
}

/**
 * @tc.name: ConvertApplicationInfo_AppUidZero_Copied
 * @tc.desc: Test ConvertApplicationInfo copies appUid when the value is zero.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, ConvertApplicationInfo_AppUidZero_Copied, TestSize.Level1)
{
    OHOS::AppExecFwk::ApplicationInfo appInfo;
    appInfo.uid = 0;
    appInfo.appUid = 0;
    EdmApplicationInfo edmApplicationInfo;
    edmApplicationInfo.uid = -1;
    edmApplicationInfo.appUid = -1;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertApplicationInfo(appInfo, edmApplicationInfo);
    ASSERT_EQ(edmApplicationInfo.uid, 0);
    ASSERT_EQ(edmApplicationInfo.appUid, 0);
}

/**
 * @tc.name: ConvertApplicationInfo_AppUidInt32Min_Copied
 * @tc.desc: Test ConvertApplicationInfo copies the minimum int32 appUid.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, ConvertApplicationInfo_AppUidInt32Min_Copied, TestSize.Level1)
{
    OHOS::AppExecFwk::ApplicationInfo appInfo;
    appInfo.uid = std::numeric_limits<int32_t>::min();
    appInfo.appUid = std::numeric_limits<int32_t>::min();
    EdmApplicationInfo edmApplicationInfo;
    edmApplicationInfo.uid = 0;
    edmApplicationInfo.appUid = 0;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertApplicationInfo(appInfo, edmApplicationInfo);
    ASSERT_EQ(edmApplicationInfo.uid, std::numeric_limits<int32_t>::min());
    ASSERT_EQ(edmApplicationInfo.appUid, std::numeric_limits<int32_t>::min());
}

/**
 * @tc.name: ConvertApplicationInfo_AppUidInt32Max_Copied
 * @tc.desc: Test ConvertApplicationInfo copies the maximum int32 appUid.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, ConvertApplicationInfo_AppUidInt32Max_Copied, TestSize.Level1)
{
    OHOS::AppExecFwk::ApplicationInfo appInfo;
    appInfo.uid = std::numeric_limits<int32_t>::max();
    appInfo.appUid = std::numeric_limits<int32_t>::max();
    EdmApplicationInfo edmApplicationInfo;
    edmApplicationInfo.uid = 0;
    edmApplicationInfo.appUid = 0;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertApplicationInfo(appInfo, edmApplicationInfo);
    ASSERT_EQ(edmApplicationInfo.uid, std::numeric_limits<int32_t>::max());
    ASSERT_EQ(edmApplicationInfo.appUid, std::numeric_limits<int32_t>::max());
}

/**
 * @tc.name: ConvertBundleInfoListItem_WithApplicationInfo_CopyAppUid
 * @tc.desc: Test ConvertBundleInfoListItem copies appUid when WITH_APPLICATION_INFO is set.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, ConvertBundleInfoListItem_WithApplicationInfo_CopyAppUid, TestSize.Level1)
{
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.applicationInfo.uid = 10001;
    bundleInfo.applicationInfo.appUid = 20002;
    EdmBundleInfo edmBundleInfo;
    uint32_t edmBundleFlag = static_cast<uint32_t>(BundleInfoGetFlag::WITH_APPLICATION_INFO);
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertBundleInfoListItem(edmBundleFlag, bundleInfo, edmBundleInfo);
    ASSERT_EQ(edmBundleInfo.applicationInfo.uid, 10001);
    ASSERT_EQ(edmBundleInfo.applicationInfo.appUid, 20002);
}

/**
 * @tc.name: ConvertBundleInfoListItem_WithoutApplicationInfo_AppUidDefault
 * @tc.desc: Test ConvertBundleInfoListItem keeps the default appUid without WITH_APPLICATION_INFO.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, ConvertBundleInfoListItem_WithoutApplicationInfo_AppUidDefault,
    TestSize.Level1)
{
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.applicationInfo.uid = 10001;
    bundleInfo.applicationInfo.appUid = 20002;
    EdmBundleInfo edmBundleInfo;
    std::shared_ptr<InstalledBundleInfoListQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    queryObj->ConvertBundleInfoListItem(0, bundleInfo, edmBundleInfo);
    ASSERT_EQ(edmBundleInfo.applicationInfo.uid, -1);
    ASSERT_EQ(edmBundleInfo.applicationInfo.appUid, -1);
}

/**
 * @tc.name: Marshalling_AppUidRoundTrip_Success
 * @tc.desc: Test EdmApplicationInfo keeps uid, appIndex and appUid after parcel round trip.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, Marshalling_AppUidRoundTrip_Success, TestSize.Level1)
{
    EdmApplicationInfo src;
    src.isSystemApp = true;
    src.uid = 10001;
    src.appIndex = 3;
    src.appUid = 20002;
    src.name = "com.test.app";
    src.iconResource.bundleName = "icon.bundle";
    src.labelResource.bundleName = "label.bundle";
    src.descriptionResource.bundleName = "desc.bundle";

    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    std::unique_ptr<EdmApplicationInfo> dest(EdmApplicationInfo::Unmarshalling(parcel));
    ASSERT_NE(dest.get(), nullptr);
    ASSERT_EQ(dest->isSystemApp, true);
    ASSERT_EQ(dest->uid, src.uid);
    ASSERT_EQ(dest->appIndex, src.appIndex);
    ASSERT_EQ(dest->name, src.name);
    ASSERT_EQ(dest->iconResource.bundleName, src.iconResource.bundleName);
    ASSERT_EQ(dest->labelResource.bundleName, src.labelResource.bundleName);
    ASSERT_EQ(dest->descriptionResource.bundleName, src.descriptionResource.bundleName);
    ASSERT_EQ(dest->appUid, src.appUid);
}

/**
 * @tc.name: Marshalling_AppUidInt32Max_Success
 * @tc.desc: Test EdmApplicationInfo parcel round trip with the maximum int32 appUid.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, Marshalling_AppUidInt32Max_Success, TestSize.Level1)
{
    EdmApplicationInfo src;
    src.appUid = std::numeric_limits<int32_t>::max();
    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    std::unique_ptr<EdmApplicationInfo> dest(EdmApplicationInfo::Unmarshalling(parcel));
    ASSERT_NE(dest.get(), nullptr);
    ASSERT_EQ(dest->appUid, std::numeric_limits<int32_t>::max());
}

/**
 * @tc.name: Marshalling_AppUidInt32Min_Success
 * @tc.desc: Test EdmApplicationInfo parcel round trip with the minimum int32 appUid.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, Marshalling_AppUidInt32Min_Success, TestSize.Level1)
{
    EdmApplicationInfo src;
    src.appUid = std::numeric_limits<int32_t>::min();
    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    std::unique_ptr<EdmApplicationInfo> dest(EdmApplicationInfo::Unmarshalling(parcel));
    ASSERT_NE(dest.get(), nullptr);
    ASSERT_EQ(dest->appUid, std::numeric_limits<int32_t>::min());
}

/**
 * @tc.name: Unmarshalling_EmptyParcel_ReturnNull
 * @tc.desc: Test EdmApplicationInfo::Unmarshalling returns null when the parcel is empty.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoListQueryTest, Unmarshalling_EmptyParcel_ReturnNull, TestSize.Level1)
{
    MessageParcel parcel;
    std::unique_ptr<EdmApplicationInfo> info(EdmApplicationInfo::Unmarshalling(parcel));
    ASSERT_EQ(info.get(), nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
