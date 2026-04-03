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

#include "edm_bundle_manager_impl.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t TEST_UID = 0;
const int32_t ILLEGAL_UID = -11;
const int32_t ILLEGAL_UID2 = 65536;
const int32_t FLAGS = 1;
const int32_t USER_ID = 1;
const int32_t INVALID_UID = -1;
const std::string EMPTY_BUNDLE_NAME = "";
const std::string INVALID_BUNDLE_NAME = "testbundlename";
const std::string BUNDLE_NAME = "com.ohos.launcher";
const std::string CONTACTS = "com.ohos.contacts";
class EdmBundleManagerImplTest : public testing::Test {};
/**
 * @tc.name: TestGetNameForUid01
 * @tc.desc: Test GetNameForUid function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestGetNameForUid01, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    std::string bundleName;
    int ret = edmBundleManagerImpl.GetNameForUid(ILLEGAL_UID, bundleName);
    ASSERT_TRUE(ret == ERR_BUNDLE_SERVICE_ABNORMALLY);

    ret = edmBundleManagerImpl.GetNameForUid(ILLEGAL_UID2, bundleName);
    ASSERT_TRUE(ret == ERR_BUNDLE_SERVICE_ABNORMALLY);
}

/**
 * @tc.name: TestGetNameForUid02
 * @tc.desc: Test GetNameForUid function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestGetNameForUid02, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    std::string bundleName;
    int ret = edmBundleManagerImpl.GetNameForUid(TEST_UID, bundleName);
    ASSERT_TRUE(ret == ERR_BUNDLE_SERVICE_ABNORMALLY);
}

/**
 * @tc.name: TestQueryExtensionAbilityInfos01
 * @tc.desc: Test QueryExtensionAbilityInfos function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestQueryExtensionAbilityInfos01, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    AAFwk::Want want;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    EXPECT_EQ(edmBundleManagerImpl.QueryExtensionAbilityInfos(
        want, AppExecFwk::ExtensionAbilityType::BACKUP, FLAGS, USER_ID, extensionInfos), false);
}

/**
 * @tc.name: TestGetBundleInfo01
 * @tc.desc: Test GetBundleInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestGetBundleInfo01, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = edmBundleManagerImpl.GetBundleInfo(
        EMPTY_BUNDLE_NAME, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USER_ID);
    EXPECT_EQ(ret, false);

    ret = edmBundleManagerImpl.GetBundleInfo(
        INVALID_BUNDLE_NAME, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USER_ID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: TestGetBundleInfo02
 * @tc.desc: Test GetBundleInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestGetBundleInfo02, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = edmBundleManagerImpl.GetBundleInfo(
        BUNDLE_NAME, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USER_ID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: TestGetApplicationUid01
 * @tc.desc: Test GetApplicationUid function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestGetApplicationUid01, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    int32_t appIndex = 0;
    int32_t uid = edmBundleManagerImpl.GetApplicationUid(EMPTY_BUNDLE_NAME, USER_ID, appIndex);
    EXPECT_EQ(uid, INVALID_UID);
    uid = edmBundleManagerImpl.GetApplicationUid(INVALID_BUNDLE_NAME, USER_ID, appIndex);
    EXPECT_EQ(uid, INVALID_UID);
}

/**
 * @tc.name: TestGetApplicationUid02
 * @tc.desc: Test GetApplicationUid function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestGetApplicationUid02, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    int32_t appIndex = 0;
    int32_t uid = edmBundleManagerImpl.GetApplicationUid(CONTACTS, 100, appIndex);
    ASSERT_FALSE(uid == INVALID_UID);
}

/**
 * @tc.name: TestGetBundleInfoV9
 * @tc.desc: Test GetBundleInfoV9 function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestGetBundleInfoV9, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = edmBundleManagerImpl.GetBundleInfoV9(
        BUNDLE_NAME, FLAGS, bundleInfo, USER_ID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: TestIsBundleInstalled
 * @tc.desc: Test IsBundleInstalled function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestIsBundleInstalled, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    int32_t appIndex = 0;
    bool ret = edmBundleManagerImpl.IsBundleInstalled(BUNDLE_NAME, USER_ID, appIndex);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: TestGetApplicationInfo
 * @tc.desc: Test GetApplicationInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestGetApplicationInfo, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    std::string result = edmBundleManagerImpl.GetApplicationInfo(BUNDLE_NAME, USER_ID);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: TestGetTokenId
 * @tc.desc: Test GetTokenId function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestGetTokenId, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    int32_t tokenId = edmBundleManagerImpl.GetTokenId(BUNDLE_NAME, USER_ID);
    EXPECT_EQ(tokenId, 0);
}

/**
 * @tc.name: TestAddAppInstallControlRule
 * @tc.desc: Test AddAppInstallControlRule function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestAddAppInstallControlRule, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    std::vector<std::string> data;
    data.push_back(BUNDLE_NAME);
    ErrCode ret = edmBundleManagerImpl.AddAppInstallControlRule(
        data, AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL, USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestDeleteAppInstallControlRule
 * @tc.desc: Test DeleteAppInstallControlRule function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestDeleteAppInstallControlRule, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    std::vector<std::string> data;
    data.push_back(BUNDLE_NAME);
    ErrCode ret = edmBundleManagerImpl.DeleteAppInstallControlRule(
        AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL, data, USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestSetDisallowedUninstall
 * @tc.desc: Test SetDisallowedUninstall function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestSetDisallowedUninstall, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    bool ret = edmBundleManagerImpl.SetDisallowedUninstall(BUNDLE_NAME, true);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: TestQueryAbilityInfo
 * @tc.desc: Test QueryAbilityInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestQueryAbilityInfo, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    AAFwk::Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    bool ret = edmBundleManagerImpl.QueryAbilityInfo(want, FLAGS, USER_ID, abilityInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: TestQueryExtensionAbilityInfos02
 * @tc.desc: Test QueryExtensionAbilityInfos function (4 parameters).
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestQueryExtensionAbilityInfos02, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    AAFwk::Want want;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    bool ret = edmBundleManagerImpl.QueryExtensionAbilityInfos(want, FLAGS, USER_ID, extensionInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: TestIsSystemApp
 * @tc.desc: Test IsSystemApp function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestIsSystemApp, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    bool isSystemApp;
    ErrCode ret = edmBundleManagerImpl.IsSystemApp(BUNDLE_NAME, USER_ID, isSystemApp);
    EXPECT_EQ(ret, EdmReturnErrCode::ABILITY_NOT_EXIST);
}

/**
 * @tc.name: TestSetApplicationDisableForbidden
 * @tc.desc: Test SetApplicationDisableForbidden function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestSetApplicationDisableForbidden, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    int32_t appIndex = 0;
    bool ret = edmBundleManagerImpl.SetApplicationDisableForbidden(BUNDLE_NAME, USER_ID, appIndex, true);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: TestGetIconByBundleName
 * @tc.desc: Test GetIconByBundleName function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBundleManagerImplTest, TestGetIconByBundleName, TestSize.Level1)
{
    EdmBundleManagerImpl edmBundleManagerImpl;
    std::string icon = edmBundleManagerImpl.GetIconByBundleName(BUNDLE_NAME);
    EXPECT_EQ(icon, "");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS