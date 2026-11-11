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

#include "manage_keep_alive_apps_info.h"

#include <gtest/gtest.h>
#include <set>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const std::string TEST_BUNDLE_A = "com.test.keepA";
const std::string TEST_BUNDLE_B = "com.test.keepB";
}

class ManageKeepAliveAppInfoTest : public testing::Test {};

/**
 * @tc.name: TestDefaults
 * @tc.desc: Test a fresh ManageKeepAliveAppInfo carries no bundle and allows modification.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppInfoTest, TestDefaults, TestSize.Level1)
{
    ManageKeepAliveAppInfo info;
    EXPECT_TRUE(info.GetBundleName().empty());
    EXPECT_FALSE(info.GetDisallowModify());
}

/**
 * @tc.name: TestSettersAndGetters
 * @tc.desc: Test the bundle name and the disallowModify flag are readable after being set.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppInfoTest, TestSettersAndGetters, TestSize.Level1)
{
    ManageKeepAliveAppInfo info;
    info.SetBundleName(TEST_BUNDLE_A);
    info.SetDisallowModify(true);
    EXPECT_EQ(info.GetBundleName(), TEST_BUNDLE_A);
    EXPECT_TRUE(info.GetDisallowModify());

    info.SetDisallowModify(false);
    EXPECT_FALSE(info.GetDisallowModify());
}

/**
 * @tc.name: TestMarshallRoundTrip
 * @tc.desc: Test ManageKeepAliveAppInfo writes and reads the same fields through a parcel.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppInfoTest, TestMarshallRoundTrip, TestSize.Level1)
{
    ManageKeepAliveAppInfo input;
    input.SetBundleName(TEST_BUNDLE_B);
    input.SetDisallowModify(true);

    MessageParcel parcel;
    EXPECT_TRUE(input.Marshalling(parcel));
    parcel.RewindRead(0);

    ManageKeepAliveAppInfo output;
    EXPECT_TRUE(ManageKeepAliveAppInfo::Unmarshalling(parcel, output));
    EXPECT_EQ(output.GetBundleName(), TEST_BUNDLE_B);
    EXPECT_TRUE(output.GetDisallowModify());
}

/**
 * @tc.name: TestUnmarshallingFromEmptyParcel
 * @tc.desc: Test Unmarshalling succeeds and overwrites the target with defaults on an empty parcel.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppInfoTest, TestUnmarshallingFromEmptyParcel, TestSize.Level1)
{
    MessageParcel parcel;
    ManageKeepAliveAppInfo output;
    output.SetBundleName(TEST_BUNDLE_A);
    EXPECT_TRUE(ManageKeepAliveAppInfo::Unmarshalling(parcel, output));
    EXPECT_TRUE(output.GetBundleName().empty());
    EXPECT_FALSE(output.GetDisallowModify());
}

/**
 * @tc.name: TestOperatorLessThan
 * @tc.desc: Test the ordering compares bundleName first and then the disallowModify flag.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppInfoTest, TestOperatorLessThan, TestSize.Level1)
{
    ManageKeepAliveAppInfo a;
    a.SetBundleName(TEST_BUNDLE_A);
    ManageKeepAliveAppInfo b;
    b.SetBundleName(TEST_BUNDLE_B);
    EXPECT_TRUE(a < b);
    EXPECT_FALSE(b < a);

    ManageKeepAliveAppInfo sameBundleFalse;
    sameBundleFalse.SetBundleName(TEST_BUNDLE_A);
    ManageKeepAliveAppInfo sameBundleTrue;
    sameBundleTrue.SetBundleName(TEST_BUNDLE_A);
    sameBundleTrue.SetDisallowModify(true);
    EXPECT_TRUE(sameBundleFalse < sameBundleTrue);
    EXPECT_FALSE(sameBundleTrue < sameBundleFalse);
    EXPECT_FALSE(sameBundleFalse < sameBundleFalse);
}

/**
 * @tc.name: TestOrderingInSet
 * @tc.desc: Test a std::set keeps distinct entries with the same bundle but different flags.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppInfoTest, TestOrderingInSet, TestSize.Level1)
{
    ManageKeepAliveAppInfo first;
    first.SetBundleName(TEST_BUNDLE_A);
    ManageKeepAliveAppInfo second;
    second.SetBundleName(TEST_BUNDLE_A);
    second.SetDisallowModify(true);
    std::set<ManageKeepAliveAppInfo> infos = { first, second, first };
    EXPECT_EQ(infos.size(), 2u);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
