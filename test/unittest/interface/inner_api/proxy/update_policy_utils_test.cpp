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
 
#include <gtest/gtest.h>

#include "update_policy_utils.h"

using namespace testing::ext;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_VERSION = "testVersion";
const std::string TEST_INSTALL_TIPS = "installTip";
const std::string TEST_INSTALL_TIPS_DEATIL = "installTipDetail";
constexpr uint32_t MAX_PACKAGES_SIZE = 10;
class UpdatePolicyUtilsTest : public testing::Test {};

/*
 *@tc.name: TestProcessPackageTypeWithUnknownType
 *@tc.desc: Test ProcessPackageType success func.
 *@tc.type: FUNC
 */
 HWTEST_F(UpdatePolicyUtilsTest, TestProcessPackageTypeWithUnknownType, TestSize.Level1)
{
    PackageType packageType;
    UpdatePolicyUtils::ProcessPackageType(static_cast<int32_t>(PackageType::UNKNOWN), packageType);
    
    ASSERT_TRUE(packageType == PackageType::UNKNOWN);
}

/*
 *@tc.name: TestProcessPackageTypeWithInllegalType
 *@tc.desc: Test ProcessPackageType success func.
 *@tc.type: FUNC
 */
  HWTEST_F(UpdatePolicyUtilsTest, TestProcessPackageTypeWithInllegalType, TestSize.Level1)
{
    PackageType packageType;
    UpdatePolicyUtils::ProcessPackageType(10, packageType);
    
    ASSERT_TRUE(packageType == PackageType::UNKNOWN);
}

/*
 *@tc.name: TestProcessPackageTypeWithFirmwareType
 *@tc.desc: Test ProcessPackageType success func.
 *@tc.type: FUNC
 */
  HWTEST_F(UpdatePolicyUtilsTest, TestProcessPackageTypeWithFirmwareType, TestSize.Level1)
{
    PackageType packageType;
    UpdatePolicyUtils::ProcessPackageType(static_cast<int32_t>(PackageType::FIRMWARE), packageType);
    
    ASSERT_TRUE(packageType == PackageType::FIRMWARE);
}

/*
 *@tc.name: TestReadUpgradePackageInfoWithPackageOutOfBund
 *@tc.desc: Test ProcessPackageType success func.
 *@tc.type: FUNC
 */
  HWTEST_F(UpdatePolicyUtilsTest, TestReadUpgradePackageInfoWithPackageOutOfBund, TestSize.Level1)
{
    MessageParcel data;
    UpgradePackageInfo packageInfo;
    std::vector<Package> packages;
    packages.insert(packages.begin(), MAX_PACKAGES_SIZE + 1, {"", PackageType::UNKNOWN, 1});
    packageInfo.version = TEST_VERSION;
    packageInfo.packages = packages;
    packageInfo.description.notify.installTips = TEST_INSTALL_TIPS;
    packageInfo.description.notify.installTipsDetail = TEST_INSTALL_TIPS_DEATIL;
    UpdatePolicyUtils::WriteUpgradePackageInfo(data, packageInfo);
    
    UpgradePackageInfo packageInfo2;
    UpdatePolicyUtils::ReadUpgradePackageInfo(data, packageInfo2);
    ASSERT_TRUE(packageInfo2.version == TEST_VERSION);
    ASSERT_TRUE(packageInfo2.packages.empty());
    ASSERT_TRUE(packageInfo2.description.notify.installTips.empty());
    ASSERT_TRUE(packageInfo2.description.notify.installTipsDetail.empty());
}

/*
 *@tc.name: TestReadUpgradePackageInfoSuc
 *@tc.desc: Test ProcessPackageType success func.
 *@tc.type: FUNC
 */
  HWTEST_F(UpdatePolicyUtilsTest, TestReadUpgradePackageInfoSuc, TestSize.Level1)
{
    MessageParcel data;
    UpgradePackageInfo packageInfo;
    std::vector<Package> packages;
    packages.insert(packages.begin(), MAX_PACKAGES_SIZE, {"", PackageType::UNKNOWN, 1});
    packageInfo.version = TEST_VERSION;
    packageInfo.packages = packages;
    packageInfo.description.notify.installTips = TEST_INSTALL_TIPS;
    packageInfo.description.notify.installTipsDetail = TEST_INSTALL_TIPS_DEATIL;
    UpdatePolicyUtils::WriteUpgradePackageInfo(data, packageInfo);
    
    UpgradePackageInfo packageInfo2;
    UpdatePolicyUtils::ReadUpgradePackageInfo(data, packageInfo2);
    ASSERT_TRUE(packageInfo2.version == TEST_VERSION);
    ASSERT_TRUE(packageInfo2.packages.size() == packages.size());
    ASSERT_TRUE(packageInfo2.description.notify.installTips == TEST_INSTALL_TIPS);
    ASSERT_TRUE(packageInfo2.description.notify.installTipsDetail == TEST_INSTALL_TIPS_DEATIL);
}

/*
 *@tc.name: TestReadUpdatePolicySuc
 *@tc.desc: Test ReadUpdatePolicy success func.
 *@tc.type: FUNC
 */
HWTEST_F(UpdatePolicyUtilsTest, TestReadUpdatePolicySuc, TestSize.Level1)
{
    MessageParcel data;
    UpdatePolicy policy;
    policy.type = UpdatePolicyType::DEFAULT;
    policy.version = TEST_VERSION;
    policy.installTime.latestUpdateTime = 0;
    policy.installTime.delayUpdateTime = 0;
    policy.installTime.installWindowStart = 0;
    policy.installTime.installWindowEnd = 0;
    policy.otaPolicyType = OtaPolicyType::DISABLE_OTA;
    UpdatePolicyUtils::WriteUpdatePolicy(data, policy);

    UpdatePolicy policy2;
    UpdatePolicyUtils::ReadUpdatePolicy(data, policy2);
    ASSERT_TRUE(policy2.type == UpdatePolicyType::DEFAULT);
    ASSERT_TRUE(policy2.version == TEST_VERSION);
    ASSERT_TRUE(policy2.installTime.latestUpdateTime == 0);
    ASSERT_TRUE(policy2.installTime.delayUpdateTime == 0);
    ASSERT_TRUE(policy2.installTime.installWindowStart == 0);
    ASSERT_TRUE(policy2.installTime.installWindowEnd == 0);
    ASSERT_TRUE(policy2.otaPolicyType == OtaPolicyType::DISABLE_OTA);
}

/*
 *@tc.name: TestProcessOtaPolicyTypeWithInllegalType
 *@tc.desc: Test ProcessOtaPolicyType success func.
 *@tc.type: FUNC
 */
  HWTEST_F(UpdatePolicyUtilsTest, TestProcessOtaPolicyTypeWithInllegalType, TestSize.Level1)
{
    OtaPolicyType otaPolicyType;
    UpdatePolicyUtils::ProcessOtaPolicyType(10, otaPolicyType);

    ASSERT_TRUE(otaPolicyType == OtaPolicyType::DEFAULT);
}

/*
 *@tc.name: TestProcessPackageTypeWithAllType
 *@tc.desc: Test ProcessOtaPolicyType success func.
 *@tc.type: FUNC
 */
 HWTEST_F(UpdatePolicyUtilsTest, TestProcessPackageTypeWithAllType, TestSize.Level1)
{
    OtaPolicyType otaPolicyType;
    UpdatePolicyUtils::ProcessOtaPolicyType(static_cast<int32_t>(OtaPolicyType::ENABLE_OTA), otaPolicyType);
    ASSERT_TRUE(otaPolicyType == OtaPolicyType::ENABLE_OTA);

    UpdatePolicyUtils::ProcessOtaPolicyType(static_cast<int32_t>(OtaPolicyType::DISABLE_OTA), otaPolicyType);
    ASSERT_TRUE(otaPolicyType == OtaPolicyType::DISABLE_OTA);

    UpdatePolicyUtils::ProcessOtaPolicyType(static_cast<int32_t>(OtaPolicyType::DEFAULT), otaPolicyType);
    ASSERT_TRUE(otaPolicyType == OtaPolicyType::DEFAULT);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS