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

#include "upgrade_package_info_serializer.h"

#include <fcntl.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include "update_policy_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class UpgradePackageInfoSerializerTest : public testing::Test {};

/**
 * @tc.name: TestSerialize
 * @tc.desc: Test UpgradePackageInfoSerializer::Serialize flags a non-empty package list.
 * @tc.type: FUNC
 */
HWTEST_F(UpgradePackageInfoSerializerTest, TestSerialize, TestSize.Level1)
{
    auto serializer = UpgradePackageInfoSerializer::GetInstance();
    UpgradePackageInfo emptyInfo;
    std::string jsonString = "unset";
    EXPECT_TRUE(serializer->Serialize(emptyInfo, jsonString));
    EXPECT_EQ(jsonString, "unset");

    UpgradePackageInfo info;
    Package package;
    package.path = "/data/update/pkg.rn";
    package.fd = -1;
    info.packages.push_back(package);
    std::string flag;
    EXPECT_TRUE(serializer->Serialize(info, flag));
    EXPECT_EQ(flag, "true");
}

/**
 * @tc.name: TestDeserialize
 * @tc.desc: Test UpgradePackageInfoSerializer::Deserialize always succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(UpgradePackageInfoSerializerTest, TestDeserialize, TestSize.Level1)
{
    auto serializer = UpgradePackageInfoSerializer::GetInstance();
    UpgradePackageInfo info;
    EXPECT_TRUE(serializer->Deserialize("", info));
    EXPECT_TRUE(serializer->Deserialize("{\"a\":1}", info));
}

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test UpgradePackageInfoSerializer::GetPolicy reads back what UpdatePolicyUtils wrote.
 * @tc.type: FUNC
 */
HWTEST_F(UpgradePackageInfoSerializerTest, TestGetPolicy, TestSize.Level1)
{
    auto serializer = UpgradePackageInfoSerializer::GetInstance();
    UpgradePackageInfo input;
    input.version = "5.0.0.100";
    input.description.notify.installTips = "tips";
    input.description.notify.installTipsDetail = "detail";
    input.authInfoSize = 4;

    MessageParcel data;
    UpdatePolicyUtils::WriteUpgradePackageInfo(data, input);
    data.RewindRead(0);

    UpgradePackageInfo output;
    EXPECT_TRUE(serializer->GetPolicy(data, output));
    EXPECT_EQ(output.version, "5.0.0.100");
    EXPECT_TRUE(output.packages.empty());
    EXPECT_EQ(output.description.notify.installTips, "tips");
    EXPECT_EQ(output.description.notify.installTipsDetail, "detail");
    EXPECT_EQ(output.authInfoSize, 4u);
}

/**
 * @tc.name: TestWritePolicyAndMergePolicy
 * @tc.desc: Test UpgradePackageInfoSerializer WritePolicy/MergePolicy return success.
 * @tc.type: FUNC
 */
HWTEST_F(UpgradePackageInfoSerializerTest, TestWritePolicyAndMergePolicy, TestSize.Level1)
{
    auto serializer = UpgradePackageInfoSerializer::GetInstance();
    MessageParcel reply;
    UpgradePackageInfo result;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));

    std::vector<UpgradePackageInfo> data = { result };
    UpgradePackageInfo merged;
    EXPECT_TRUE(serializer->MergePolicy(data, merged));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
