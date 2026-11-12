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

#include "edm_application_info.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr uint32_t TEST_RES_ID = 1001;
constexpr uint32_t TEST_DEFAULT_RES_ID = 0;
const std::string TEST_RES_BUNDLE = "com.test.res";
const std::string TEST_RES_MODULE = "entry";
const std::string TEST_APP_NAME = "com.test.app";
}

class EdmApplicationInfoTest : public testing::Test {};

/**
 * @tc.name: TestEdmResourceMarshallRoundTrip
 * @tc.desc: Test EdmResource Marshalling/Unmarshalling keeps id, bundleName and moduleName.
 * @tc.type: FUNC
 */
HWTEST_F(EdmApplicationInfoTest, TestEdmResourceMarshallRoundTrip, TestSize.Level1)
{
    EdmResource input;
    input.id = TEST_RES_ID;
    input.bundleName = TEST_RES_BUNDLE;
    input.moduleName = TEST_RES_MODULE;

    MessageParcel parcel;
    EXPECT_TRUE(input.Marshalling(parcel));
    parcel.RewindRead(0);

    EdmResource *output = EdmResource::Unmarshalling(parcel);
    ASSERT_NE(output, nullptr);
    EXPECT_EQ(output->id, TEST_RES_ID);
    EXPECT_EQ(output->bundleName, TEST_RES_BUNDLE);
    EXPECT_EQ(output->moduleName, TEST_RES_MODULE);
    delete output;
}

/**
 * @tc.name: TestEdmResourceUnmarshallingFromEmptyParcel
 * @tc.desc: Test EdmResource::Unmarshalling yields an object with default fields for an empty parcel.
 * @tc.type: FUNC
 */
HWTEST_F(EdmApplicationInfoTest, TestEdmResourceUnmarshallingFromEmptyParcel, TestSize.Level1)
{
    MessageParcel parcel;
    EdmResource *output = EdmResource::Unmarshalling(parcel);
    ASSERT_NE(output, nullptr);
    EXPECT_EQ(output->id, TEST_DEFAULT_RES_ID);
    EXPECT_TRUE(output->bundleName.empty());
    EXPECT_TRUE(output->moduleName.empty());
    delete output;
}

/**
 * @tc.name: TestEdmApplicationInfoMarshallRoundTrip
 * @tc.desc: Test EdmApplicationInfo Marshalling/Unmarshalling keeps the scalar and string fields.
 * @tc.type: FUNC
 */
HWTEST_F(EdmApplicationInfoTest, TestEdmApplicationInfoMarshallRoundTrip, TestSize.Level1)
{
    EdmApplicationInfo input;
    input.removable = false;
    input.isSystemApp = true;
    input.debug = true;
    input.userDataClearable = false;
    input.enabled = true;
    input.accessTokenId = 12345;
    input.iconId = 1;
    input.labelId = 2;
    input.descriptionId = 3;
    input.uid = 20010;
    input.appIndex = 1;
    input.name = TEST_APP_NAME;
    input.description = "desc";
    input.label = "label";
    input.icon = "icon.png";
    input.iconData = "iconData";
    input.process = "testProcess";
    input.codePath = "/data/app/test";
    input.appDistributionType = "internalTest";
    input.appProvisionType = "releaseType";
    input.nativeLibraryPath = "/data/app/test/lib";
    input.installSource = "com.test.source";
    input.apiReleaseType = "ReleaseType";
    input.iconResource.id = TEST_RES_ID;
    input.iconResource.bundleName = TEST_RES_BUNDLE;
    input.iconResource.moduleName = TEST_RES_MODULE;

    MessageParcel parcel;
    EXPECT_TRUE(input.Marshalling(parcel));
    parcel.RewindRead(0);

    EdmApplicationInfo *output = EdmApplicationInfo::Unmarshalling(parcel);
    ASSERT_NE(output, nullptr);
    EXPECT_EQ(output->removable, false);
    EXPECT_EQ(output->isSystemApp, true);
    EXPECT_EQ(output->debug, true);
    EXPECT_EQ(output->userDataClearable, false);
    EXPECT_EQ(output->enabled, true);
    EXPECT_EQ(output->accessTokenId, 12345u);
    EXPECT_EQ(output->uid, 20010);
    EXPECT_EQ(output->appIndex, 1);
    EXPECT_EQ(output->name, TEST_APP_NAME);
    EXPECT_EQ(output->label, "label");
    EXPECT_EQ(output->codePath, "/data/app/test");
    EXPECT_EQ(output->appDistributionType, "internalTest");
    EXPECT_EQ(output->installSource, "com.test.source");
    EXPECT_EQ(output->iconResource.id, TEST_RES_ID);
    EXPECT_EQ(output->iconResource.bundleName, TEST_RES_BUNDLE);
    delete output;
}

/**
 * @tc.name: TestEdmApplicationInfoDefaults
 * @tc.desc: Test EdmApplicationInfo keeps the documented default values.
 * @tc.type: FUNC
 */
HWTEST_F(EdmApplicationInfoTest, TestEdmApplicationInfoDefaults, TestSize.Level1)
{
    EdmApplicationInfo info;
    EXPECT_EQ(info.removable, true);
    EXPECT_EQ(info.userDataClearable, true);
    EXPECT_EQ(info.enabled, false);
    EXPECT_EQ(info.uid, -1);
    EXPECT_EQ(info.appDistributionType, EdmConstants::APP_DISTRIBUTION_TYPE_NONE);
    EXPECT_EQ(info.appProvisionType, EdmConstants::APP_PROVISION_TYPE_RELEASE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
