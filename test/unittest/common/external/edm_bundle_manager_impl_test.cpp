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
const std::string EMPTY_BUNDLE_NAME = "";
const std::string INVALID_BUNDLE_NAME = "testbundlename";
const std::string BUNDLE_NAME = "com.ohos.launcher";
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
} // namespace TEST
} // namespace EDM
} // namespace OHOS