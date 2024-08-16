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

#include "edm_os_account_manager_impl.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t TEST_ACCOUNT_ID = 100;
const int32_t ILLEGAL_ACCOUNT_ID = -100;
const int32_t ILLEGAL_ACCOUNT_ID2 = 2147483647;
#ifdef OS_ACCOUNT_EDM_ENABLE
const int32_t ACCOUNT_NAME_LENGTH_MAX = 1024;
#endif
class EdmOsAccountManagerImplTest : public testing::Test {};
/**
 * @tc.name: TestQueryActiveOsAccountIds01
 * @tc.desc: Test QueryActiveOsAccountIds function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmOsAccountManagerImplTest, TestQueryActiveOsAccountIds01, TestSize.Level1)
{
    EdmOsAccountManagerImpl edmOsAccountManagerImpl;
    std::vector<int32_t> ids;
    int ret = edmOsAccountManagerImpl.QueryActiveOsAccountIds(ids);
#ifdef OS_ACCOUNT_EDM_ENABLE
    ASSERT_TRUE(ret == ERR_OK);
#else
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
#endif
}

/**
 * @tc.name: TestQueryActiveOsAccountIds02
 * @tc.desc: Test QueryActiveOsAccountIds function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmOsAccountManagerImplTest, TestQueryActiveOsAccountIds02, TestSize.Level1)
{
    EdmOsAccountManagerImpl edmOsAccountManagerImpl;
    std::vector<int32_t> ids;
    ids.push_back(ILLEGAL_ACCOUNT_ID);
    int ret = edmOsAccountManagerImpl.QueryActiveOsAccountIds(ids);
#ifdef OS_ACCOUNT_EDM_ENABLE
    ASSERT_TRUE(ret == ERR_OK);
#else
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
#endif

    ids.clear();
    ids.push_back(ILLEGAL_ACCOUNT_ID2);
    ret = edmOsAccountManagerImpl.QueryActiveOsAccountIds(ids);
#ifdef OS_ACCOUNT_EDM_ENABLE
    ASSERT_TRUE(ret == ERR_OK);
#else
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
#endif

    ids.clear();
    ids.push_back(ILLEGAL_ACCOUNT_ID);
    ids.push_back(ILLEGAL_ACCOUNT_ID2);
    ids.push_back(TEST_ACCOUNT_ID);
    ret = edmOsAccountManagerImpl.QueryActiveOsAccountIds(ids);
#ifdef OS_ACCOUNT_EDM_ENABLE
    ASSERT_TRUE(ret == ERR_OK);
#else
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
#endif
}

/**
 * @tc.name: TestQueryActiveOsAccountIds03
 * @tc.desc: Test QueryActiveOsAccountIds function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmOsAccountManagerImplTest, TestQueryActiveOsAccountIds03, TestSize.Level1)
{
    EdmOsAccountManagerImpl edmOsAccountManagerImpl;
    std::vector<int32_t> ids;
    ids.push_back(TEST_ACCOUNT_ID);
    int ret = edmOsAccountManagerImpl.QueryActiveOsAccountIds(ids);
#ifdef OS_ACCOUNT_EDM_ENABLE
    ASSERT_TRUE(ret == ERR_OK);
#else
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
#endif
}

/**
 * @tc.name: TestIsOsAccountExists01
 * @tc.desc: Test IsOsAccountExists function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmOsAccountManagerImplTest, TestIsOsAccountExists01, TestSize.Level1)
{
    EdmOsAccountManagerImpl edmOsAccountManagerImpl;
    bool isExist;
    edmOsAccountManagerImpl.IsOsAccountExists(ILLEGAL_ACCOUNT_ID, isExist);
    ASSERT_FALSE(isExist);

    edmOsAccountManagerImpl.IsOsAccountExists(ILLEGAL_ACCOUNT_ID2, isExist);
    ASSERT_FALSE(isExist);
}

/**
 * @tc.name: TestIsOsAccountExists02
 * @tc.desc: Test IsOsAccountExists function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmOsAccountManagerImplTest, TestIsOsAccountExists02, TestSize.Level1)
{
    EdmOsAccountManagerImpl edmOsAccountManagerImpl;
    bool isExist;
#ifdef OS_ACCOUNT_EDM_ENABLE
    edmOsAccountManagerImpl.IsOsAccountExists(TEST_ACCOUNT_ID, isExist);
    ASSERT_TRUE(isExist);
#else
    int ret = edmOsAccountManagerImpl.IsOsAccountExists(TEST_ACCOUNT_ID, isExist);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
#endif
}

#ifdef OS_ACCOUNT_EDM_ENABLE
/**
 * @tc.name: TestCreateOsAccount
 * @tc.desc: Test CreateOsAccount function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmOsAccountManagerImplTest, TestCreateOsAccount, TestSize.Level1)
{
    EdmOsAccountManagerImpl edmOsAccountManagerImpl;
    OHOS::AccountSA::OsAccountType type = OHOS::AccountSA::OsAccountType::ADMIN;
    std::string name = "testName";
    for (int i = 0; i < ACCOUNT_NAME_LENGTH_MAX; i++) {
        name.append("z");
    }
    OHOS::AccountSA::OsAccountInfo accountInfo;
    int ret = edmOsAccountManagerImpl.CreateOsAccount(name, type, accountInfo);
    ASSERT_TRUE(ret != ERR_OK);
}
#endif
} // namespace TEST
} // namespace EDM
} // namespace OHOS