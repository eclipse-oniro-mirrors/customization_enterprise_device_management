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
 
#include <gtest/gtest.h>
#include <memory>
#include <string>
 
#include "get_application_icon_data_query.h"
 
#include "edm_constants.h"
#include "edm_errors.h"
 
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;
 
namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_ICON_BUNDLE_NAME = "com.example.myapplication";
 
class GetApplicationIconDataQueryTest : public testing::Test {
protected:
    void SetUp() override;
 
    void TearDown() override;
};
 
void GetApplicationIconDataQueryTest::SetUp() {}
 
void GetApplicationIconDataQueryTest::TearDown() {}
 
/**
 * @tc.name: GetApplicationIconDataQueryBasicInfo
 * @tc.desc: Test GetApplicationIconDataQuery GetPolicyName and GetPermission.
 * @tc.type: FUNC
 */
HWTEST_F(GetApplicationIconDataQueryTest, GetApplicationIconDataQueryBasicInfo, TestSize.Level1)
{
    std::shared_ptr<GetApplicationIconDataQuery> queryObj = std::make_shared<GetApplicationIconDataQuery>();
    ASSERT_NE(queryObj, nullptr);
    EXPECT_EQ(queryObj->GetPolicyName(), PolicyName::POLICY_GET_APPLICATION_ICON_DATA);
    EXPECT_EQ(queryObj->GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    EXPECT_EQ(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    EXPECT_EQ(queryObj->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "test_permission_tag"),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
}
 
/**
 * @tc.name: TestQueryPolicyBmsUnavailable
 * @tc.desc: Test GetApplicationIconDataQuery::QueryPolicy when bundle manager service is unavailable.
 * @tc.type: FUNC
 */
HWTEST_F(GetApplicationIconDataQueryTest, TestQueryPolicyBmsUnavailable, TestSize.Level1)
{
    std::shared_ptr<GetApplicationIconDataQuery> queryObj = std::make_shared<GetApplicationIconDataQuery>();
    ASSERT_NE(queryObj, nullptr);
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(TEST_ICON_BUNDLE_NAME);
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::DOCK_APP_NOT_INSTALLED);
    EXPECT_EQ(reply.GetDataSize(), 0u);
}
 
/**
 * @tc.name: TestQueryPolicyBundleNameEmpty
 * @tc.desc: Test GetApplicationIconDataQuery::QueryPolicy with empty bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(GetApplicationIconDataQueryTest, TestQueryPolicyBundleNameEmpty, TestSize.Level1)
{
    std::shared_ptr<GetApplicationIconDataQuery> queryObj = std::make_shared<GetApplicationIconDataQuery>();
    ASSERT_NE(queryObj, nullptr);
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::DOCK_APP_NOT_INSTALLED);
    EXPECT_EQ(reply.GetDataSize(), 0u);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
