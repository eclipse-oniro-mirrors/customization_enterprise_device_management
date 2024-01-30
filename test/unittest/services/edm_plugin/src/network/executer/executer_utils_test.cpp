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

#include "executer_utils.h"

#include <gtest/gtest.h>
#include <memory>

#include "utils.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::EDM::IPTABLES;
using namespace OHOS::EDM::TEST;

namespace OHOS {
namespace EDM {
namespace IPTABLES {
namespace TEST {

class ExecuterUtilsTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void ExecuterUtilsTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ExecuterUtilsTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestExecute
 * @tc.desc: Test Execute func.
 * @tc.type: FUNC
 */
HWTEST_F(ExecuterUtilsTest, TestExecute, TestSize.Level1)
{
    std::shared_ptr<ExecuterUtils> executerUtils = std::make_shared<ExecuterUtils>();

    std::string rule = "-t filter -N edm_unit_test_output";
    std::string result;
    ErrCode ret = executerUtils->Execute(rule, result);
    ASSERT_TRUE(ret == ERR_OK);

    rule = "-t filter -I OUTPUT -j edm_unit_test_output";
    ret = executerUtils->Execute(rule, result);
    ASSERT_TRUE(ret == ERR_OK);

    rule = "-t filter -F edm_unit_test_output";
    ret = executerUtils->Execute(rule, result);
    ASSERT_TRUE(ret == ERR_OK);

    rule = "-t filter -n -v -L edm_unit_test_output --line-number";
    ret = executerUtils->Execute(rule, result);
    ASSERT_TRUE(ret == ERR_OK);

    std::istringstream iss(result);
    std::vector<std::string> ruleLines;
    std::string line;
    while (getline(iss, line)) {
        ruleLines.emplace_back(line);
    }
    ASSERT_TRUE(ruleLines.size() == 2);

    rule = "-t filter -D OUTPUT -j edm_unit_test_output";
    ret = executerUtils->Execute(rule, result);
    ASSERT_TRUE(ret == ERR_OK);

    rule = "-t filter -X edm_unit_test_output";
    ret = executerUtils->Execute(rule, result);
    ASSERT_TRUE(ret == ERR_OK);

    rule = "-t filter -n -v -L edm_unit_test_output --line-number";
    ret = executerUtils->Execute(rule, result);
    ASSERT_TRUE(result.empty());
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS