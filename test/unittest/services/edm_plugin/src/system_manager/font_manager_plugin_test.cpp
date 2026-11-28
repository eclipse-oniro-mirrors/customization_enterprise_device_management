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

#include "font_manager_plugin.h"

#include <fcntl.h>
#include <unistd.h>

#include <cstdlib>

#include <gtest/gtest.h>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "message_parcel.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr const char *NON_REGULAR_FILE_PATH = "/dev/null";
// Font manager inner error codes (see font_define.h FontErrorCode and font_manager_plugin.cpp).
constexpr int32_t FONT_MANAGER_ERR_OK = 0;
constexpr int32_t FONT_MANAGER_ERR_FILE_NOT_EXISTS = 31100101;
constexpr int32_t FONT_MANAGER_ERR_FILE_VERIFY_FAIL = 31100102;
constexpr int32_t FONT_MANAGER_ERR_COPY_FAIL = 31100103;
constexpr int32_t FONT_MANAGER_ERR_INSTALLED_ALREADY = 31100104;
constexpr int32_t FONT_MANAGER_ERR_MAX_FILE_COUNT = 31100105;
constexpr int32_t FONT_MANAGER_ERR_INSTALL_FAIL = 31100106;
constexpr int32_t FONT_MANAGER_ERR_UNINSTALL_FILE_NOT_EXISTS = 31100107;
constexpr int32_t FONT_MANAGER_ERR_UNINSTALL_REMOVE_FAIL = 31100108;
constexpr int32_t FONT_MANAGER_ERR_UNINSTALL_FAIL = 31100109;

class FontManagerPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void FontManagerPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void FontManagerPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyUnsupportedOperateType
 * @tc.desc: Test FontManagerPlugin::OnHandlePolicy with unsupported operate type (GET). SET and REMOVE
 *           are dispatched to install/uninstall, any other operate type must return
 *           PARAMETER_VERIFICATION_FAILED regardless of the payload.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestOnHandlePolicyUnsupportedOperateType, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<FontManagerPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET,
        EdmInterfaceCode::FONT_MANAGER);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyInstallMissingFileDescriptor
 * @tc.desc: Test FontManagerPlugin::OnHandlePolicy(SET) with an empty parcel (no file descriptor).
 *           ReadFileDescriptor returns a negative value, so the request is rejected with
 *           FONT_FILE_NOT_EXISTS.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestOnHandlePolicyInstallMissingFileDescriptor, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<FontManagerPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::FONT_MANAGER);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::FONT_FILE_NOT_EXISTS);
}

/**
 * @tc.name: TestOnHandlePolicyInstallEmptyFontFile
 * @tc.desc: Test FontManagerPlugin::OnHandlePolicy(SET) with a regular but empty (size 0) file. The
 *           plugin-level fd guard (fstat size check) rejects it with FONT_FILE_VERIFY_FAIL.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestOnHandlePolicyInstallEmptyFontFile, TestSize.Level1)
{
    char tmpFile[] = "/data/test_font_XXXXXX.ttf";
    int32_t fd = mkstemps(tmpFile, 4);
    ASSERT_NE(fd, -1);
    fdsan_exchange_owner_tag(fd, 0, EdmConstants::LOG_DOMAINID);

    MessageParcel data;
    MessageParcel reply;
    data.WriteFileDescriptor(fd);
    auto plugin = std::make_shared<FontManagerPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::FONT_MANAGER);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::FONT_FILE_VERIFY_FAIL);

    fdsan_close_with_tag(fd, EdmConstants::LOG_DOMAINID);
    unlink(tmpFile);
}

/**
 * @tc.name: TestOnHandlePolicyInstallNonRegularFile
 * @tc.desc: Test FontManagerPlugin::OnHandlePolicy(SET) with /dev/null as the fd source. fstat reports
 *           a non-regular file, so the plugin-level fd guard rejects it with INVALID_PATH (9201072).
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestOnHandlePolicyInstallNonRegularFile, TestSize.Level1)
{
    int32_t fd = open(NON_REGULAR_FILE_PATH, O_RDONLY);
    ASSERT_NE(fd, -1);
    fdsan_exchange_owner_tag(fd, 0, EdmConstants::LOG_DOMAINID);

    MessageParcel data;
    MessageParcel reply;
    data.WriteFileDescriptor(fd);
    auto plugin = std::make_shared<FontManagerPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::FONT_MANAGER);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INVALID_PATH);

    fdsan_close_with_tag(fd, EdmConstants::LOG_DOMAINID);
}

/**
 * @tc.name: TestOnHandlePolicyUninstallEmptyFontName
 * @tc.desc: Test FontManagerPlugin::OnHandlePolicy(REMOVE) with empty fontName.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestOnHandlePolicyUninstallEmptyFontName, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    auto plugin = std::make_shared<FontManagerPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::FONT_MANAGER);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyUninstallReadFontNameFailed
 * @tc.desc: Test FontManagerPlugin::OnHandlePolicy(REMOVE) when no string is written to data parcel.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestOnHandlePolicyUninstallReadFontNameFailed, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<FontManagerPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::FONT_MANAGER);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestMapFontManagerErrCodeOk
 * @tc.desc: Test FontManagerPlugin::MapFontManagerErrCode with inner code 0 maps to ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestMapFontManagerErrCodeOk, TestSize.Level1)
{
    ErrCode ret = FontManagerPlugin::MapFontManagerErrCode(FONT_MANAGER_ERR_OK);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestMapFontManagerErrCodeFileNotExists
 * @tc.desc: Test FontManagerPlugin::MapFontManagerErrCode with 31100101 maps to FONT_FILE_NOT_EXISTS.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestMapFontManagerErrCodeFileNotExists, TestSize.Level1)
{
    ErrCode ret = FontManagerPlugin::MapFontManagerErrCode(FONT_MANAGER_ERR_FILE_NOT_EXISTS);
    EXPECT_EQ(ret, static_cast<ErrCode>(EdmReturnErrCode::FONT_FILE_NOT_EXISTS));
}

/**
 * @tc.name: TestMapFontManagerErrCodeFileVerifyFail
 * @tc.desc: Test FontManagerPlugin::MapFontManagerErrCode with 31100102 maps to FONT_FILE_VERIFY_FAIL.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestMapFontManagerErrCodeFileVerifyFail, TestSize.Level1)
{
    ErrCode ret = FontManagerPlugin::MapFontManagerErrCode(FONT_MANAGER_ERR_FILE_VERIFY_FAIL);
    EXPECT_EQ(ret, static_cast<ErrCode>(EdmReturnErrCode::FONT_FILE_VERIFY_FAIL));
}

/**
 * @tc.name: TestMapFontManagerErrCodeInstalledAlready
 * @tc.desc: Test FontManagerPlugin::MapFontManagerErrCode with 31100104 maps to FONT_INSTALLED_ALREADY.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestMapFontManagerErrCodeInstalledAlready, TestSize.Level1)
{
    ErrCode ret = FontManagerPlugin::MapFontManagerErrCode(FONT_MANAGER_ERR_INSTALLED_ALREADY);
    EXPECT_EQ(ret, static_cast<ErrCode>(EdmReturnErrCode::FONT_INSTALLED_ALREADY));
}

/**
 * @tc.name: TestMapFontManagerErrCodeMaxFileCount
 * @tc.desc: Test FontManagerPlugin::MapFontManagerErrCode with 31100105 maps to FONT_MAX_FILE_COUNT.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestMapFontManagerErrCodeMaxFileCount, TestSize.Level1)
{
    ErrCode ret = FontManagerPlugin::MapFontManagerErrCode(FONT_MANAGER_ERR_MAX_FILE_COUNT);
    EXPECT_EQ(ret, static_cast<ErrCode>(EdmReturnErrCode::FONT_MAX_FILE_COUNT));
}

/**
 * @tc.name: TestMapFontManagerErrCodeUninstallFileNotExists
 * @tc.desc: Test FontManagerPlugin::MapFontManagerErrCode with 31100107 maps to FONT_UNINSTALL_NOT_EXISTS.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestMapFontManagerErrCodeUninstallFileNotExists, TestSize.Level1)
{
    ErrCode ret = FontManagerPlugin::MapFontManagerErrCode(FONT_MANAGER_ERR_UNINSTALL_FILE_NOT_EXISTS);
    EXPECT_EQ(ret, static_cast<ErrCode>(EdmReturnErrCode::FONT_UNINSTALL_NOT_EXISTS));
}

/**
 * @tc.name: TestMapFontManagerErrCodeGenericFailCodes
 * @tc.desc: Test FontManagerPlugin::MapFontManagerErrCode with copy/install/uninstall-remove/uninstall
 *           generic failure codes (31100103/31100106/31100108/31100109) maps to EXECUTE_TIME_OUT.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestMapFontManagerErrCodeGenericFailCodes, TestSize.Level1)
{
    EXPECT_EQ(FontManagerPlugin::MapFontManagerErrCode(FONT_MANAGER_ERR_COPY_FAIL),
        static_cast<ErrCode>(EdmReturnErrCode::EXECUTE_TIME_OUT));
    EXPECT_EQ(FontManagerPlugin::MapFontManagerErrCode(FONT_MANAGER_ERR_INSTALL_FAIL),
        static_cast<ErrCode>(EdmReturnErrCode::EXECUTE_TIME_OUT));
    EXPECT_EQ(FontManagerPlugin::MapFontManagerErrCode(FONT_MANAGER_ERR_UNINSTALL_REMOVE_FAIL),
        static_cast<ErrCode>(EdmReturnErrCode::EXECUTE_TIME_OUT));
    EXPECT_EQ(FontManagerPlugin::MapFontManagerErrCode(FONT_MANAGER_ERR_UNINSTALL_FAIL),
        static_cast<ErrCode>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: TestMapFontManagerErrCodeUnknownCode
 * @tc.desc: Test FontManagerPlugin::MapFontManagerErrCode with an unmapped/unknown code falls to the
 *           default branch and maps to EXECUTE_TIME_OUT.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestMapFontManagerErrCodeUnknownCode, TestSize.Level1)
{
    EXPECT_EQ(FontManagerPlugin::MapFontManagerErrCode(-1),
        static_cast<ErrCode>(EdmReturnErrCode::EXECUTE_TIME_OUT));
    EXPECT_EQ(FontManagerPlugin::MapFontManagerErrCode(1),
        static_cast<ErrCode>(EdmReturnErrCode::EXECUTE_TIME_OUT));
    EXPECT_EQ(FontManagerPlugin::MapFontManagerErrCode(31100110),
        static_cast<ErrCode>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: TestMapFontManagerErrCodeBoundaryValues
 * @tc.desc: Test FontManagerPlugin::MapFontManagerErrCode with boundary values around the known inner
 *           error code range (31100100 and 31100199) falls to the default branch.
 * @tc.type: FUNC
 */
HWTEST_F(FontManagerPluginTest, TestMapFontManagerErrCodeBoundaryValues, TestSize.Level1)
{
    EXPECT_EQ(FontManagerPlugin::MapFontManagerErrCode(31100100),
        static_cast<ErrCode>(EdmReturnErrCode::EXECUTE_TIME_OUT));
    EXPECT_EQ(FontManagerPlugin::MapFontManagerErrCode(31100199),
        static_cast<ErrCode>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
