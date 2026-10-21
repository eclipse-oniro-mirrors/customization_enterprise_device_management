#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "managed_event.h"
#include "sensitive_api_whitelist.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class SensitiveApiWhitelistTest : public testing::Test {};

/**
 * @tc.name: TestIsSensitive_GetCallLogs_ReturnTrue
 * @tc.desc: Test IsSensitive with GET_CALL_LOGS policy id.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestIsSensitive_GetCallLogs_ReturnTrue, TestSize.Level1)
{
    uint32_t policyCode = static_cast<uint32_t>(EdmInterfaceCode::GET_CALL_LOGS);
    std::string sensitiveId = SensitiveApiWhitelist::MakePolicyId(policyCode);
    EXPECT_FALSE(sensitiveId.empty());
    bool result = SensitiveApiWhitelist::IsSensitive(sensitiveId);
    EXPECT_TRUE(result);
    std::string body = SensitiveApiWhitelist::GetBodyTemplateName(sensitiveId);
    EXPECT_FALSE(body.empty());
    EXPECT_EQ(body, "sensitive_call_notification_body_call_record");
}

/**
 * @tc.name: TestIsSensitive_GetSmsMessages_ReturnTrue
 * @tc.desc: Test IsSensitive with GET_SMS_MESSAGES policy id.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestIsSensitive_GetSmsMessages_ReturnTrue, TestSize.Level1)
{
    uint32_t policyCode = static_cast<uint32_t>(EdmInterfaceCode::GET_SMS_MESSAGES);
    std::string sensitiveId = SensitiveApiWhitelist::MakePolicyId(policyCode);
    EXPECT_FALSE(sensitiveId.empty());
    bool result = SensitiveApiWhitelist::IsSensitive(sensitiveId);
    EXPECT_TRUE(result);
    std::string body = SensitiveApiWhitelist::GetBodyTemplateName(sensitiveId);
    EXPECT_FALSE(body.empty());
    EXPECT_EQ(body, "sensitive_call_notification_body_sms_record");
}

/**
 * @tc.name: TestIsSensitive_SmsReceivedEvent_ReturnTrue
 * @tc.desc: Test IsSensitive with SMS_RECEIVED event id (EVENT type, not POLICY).
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestIsSensitive_SmsReceivedEvent_ReturnTrue, TestSize.Level1)
{
    uint32_t managedEvent = static_cast<uint32_t>(ManagedEvent::SMS_RECEIVED);
    std::string sensitiveId = SensitiveApiWhitelist::MakeEventId(managedEvent);
    EXPECT_FALSE(sensitiveId.empty());
    bool result = SensitiveApiWhitelist::IsSensitive(sensitiveId);
    EXPECT_TRUE(result);
    std::string body = SensitiveApiWhitelist::GetBodyTemplateName(sensitiveId);
    EXPECT_FALSE(body.empty());
    EXPECT_EQ(body, "sensitive_call_notification_body_sms_broadcast");
}

/**
 * @tc.name: TestIsSensitive_NonWhitelistedPolicy_ReturnFalse
 * @tc.desc: Test IsSensitive with a non-whitelisted policy id.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestIsSensitive_NonWhitelistedPolicy_ReturnFalse, TestSize.Level1)
{
    uint32_t policyCode = static_cast<uint32_t>(EdmInterfaceCode::POLICY_CODE_END);
    std::string sensitiveId = SensitiveApiWhitelist::MakePolicyId(policyCode);
    EXPECT_FALSE(sensitiveId.empty());
    bool result = SensitiveApiWhitelist::IsSensitive(sensitiveId);
    EXPECT_FALSE(result);
    EXPECT_TRUE(SensitiveApiWhitelist::GetBodyTemplateName(sensitiveId).empty());
}

/**
 * @tc.name: TestIsSensitive_NonWhitelistedEvent_ReturnFalse
 * @tc.desc: Test IsSensitive with a non-whitelisted event id.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestIsSensitive_NonWhitelistedEvent_ReturnFalse, TestSize.Level1)
{
    uint32_t managedEvent = 99;
    std::string sensitiveId = SensitiveApiWhitelist::MakeEventId(managedEvent);
    EXPECT_FALSE(sensitiveId.empty());
    bool result = SensitiveApiWhitelist::IsSensitive(sensitiveId);
    EXPECT_FALSE(result);
    EXPECT_TRUE(SensitiveApiWhitelist::GetBodyTemplateName(sensitiveId).empty());
}

/**
 * @tc.name: TestIsSensitive_EmptyId_ReturnFalse
 * @tc.desc: Test IsSensitive with an empty string and invalid format.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestIsSensitive_EmptyId_ReturnFalse, TestSize.Level1)
{
    std::string emptyId;
    EXPECT_TRUE(emptyId.empty());
    bool result = SensitiveApiWhitelist::IsSensitive(emptyId);
    EXPECT_FALSE(result);
    EXPECT_FALSE(SensitiveApiWhitelist::IsSensitive(""));
    EXPECT_FALSE(SensitiveApiWhitelist::IsSensitive("UNKNOWN:123"));
    EXPECT_TRUE(SensitiveApiWhitelist::GetBodyTemplateName("").empty());
}

/**
 * @tc.name: TestGetBodyTemplateName_GetCallLogs_ReturnCallRecordTemplate
 * @tc.desc: Test GetBodyTemplateName returns call_record template for GET_CALL_LOGS.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestGetBodyTemplateName_GetCallLogs_ReturnCallRecordTemplate, TestSize.Level1)
{
    uint32_t policyCode = static_cast<uint32_t>(EdmInterfaceCode::GET_CALL_LOGS);
    std::string sensitiveId = SensitiveApiWhitelist::MakePolicyId(policyCode);
    std::string templateName = SensitiveApiWhitelist::GetBodyTemplateName(sensitiveId);
    EXPECT_FALSE(templateName.empty());
    EXPECT_EQ(templateName, "sensitive_call_notification_body_call_record");
    EXPECT_TRUE(SensitiveApiWhitelist::IsSensitive(sensitiveId));
}

/**
 * @tc.name: TestGetBodyTemplateName_GetSmsMessages_ReturnSmsRecordTemplate
 * @tc.desc: Test GetBodyTemplateName returns sms_record template for GET_SMS_MESSAGES.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestGetBodyTemplateName_GetSmsMessages_ReturnSmsRecordTemplate, TestSize.Level1)
{
    uint32_t policyCode = static_cast<uint32_t>(EdmInterfaceCode::GET_SMS_MESSAGES);
    std::string sensitiveId = SensitiveApiWhitelist::MakePolicyId(policyCode);
    std::string templateName = SensitiveApiWhitelist::GetBodyTemplateName(sensitiveId);
    EXPECT_FALSE(templateName.empty());
    EXPECT_EQ(templateName, "sensitive_call_notification_body_sms_record");
    EXPECT_TRUE(SensitiveApiWhitelist::IsSensitive(sensitiveId));
}

/**
 * @tc.name: TestGetBodyTemplateName_SmsReceived_ReturnSmsBroadcastTemplate
 * @tc.desc: Test GetBodyTemplateName returns sms_broadcast template for SMS_RECEIVED event.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestGetBodyTemplateName_SmsReceived_ReturnSmsBroadcastTemplate, TestSize.Level1)
{
    uint32_t managedEvent = static_cast<uint32_t>(ManagedEvent::SMS_RECEIVED);
    std::string sensitiveId = SensitiveApiWhitelist::MakeEventId(managedEvent);
    std::string templateName = SensitiveApiWhitelist::GetBodyTemplateName(sensitiveId);
    EXPECT_FALSE(templateName.empty());
    EXPECT_EQ(templateName, "sensitive_call_notification_body_sms_broadcast");
    EXPECT_TRUE(SensitiveApiWhitelist::IsSensitive(sensitiveId));
}

/**
 * @tc.name: TestGetBodyTemplateName_UnknownId_ReturnEmpty
 * @tc.desc: Test GetBodyTemplateName with an unknown id returns empty.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestGetBodyTemplateName_UnknownId_ReturnEmpty, TestSize.Level1)
{
    uint32_t policyCode = static_cast<uint32_t>(EdmInterfaceCode::POLICY_CODE_END);
    std::string sensitiveId = SensitiveApiWhitelist::MakePolicyId(policyCode);
    std::string templateName = SensitiveApiWhitelist::GetBodyTemplateName(sensitiveId);
    EXPECT_TRUE(templateName.empty());
    EXPECT_FALSE(SensitiveApiWhitelist::IsSensitive(sensitiveId));
}

/**
 * @tc.name: TestMakePolicyId_ValidCode_ReturnCorrectFormat
 * @tc.desc: Test MakePolicyId with a valid policy code returns POLICY prefix.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestMakePolicyId_ValidCode_ReturnCorrectFormat, TestSize.Level1)
{
    uint32_t policyCode = static_cast<uint32_t>(EdmInterfaceCode::GET_CALL_LOGS);
    std::string result = SensitiveApiWhitelist::MakePolicyId(policyCode);
    EXPECT_FALSE(result.empty());
    EXPECT_TRUE(result.find("POLICY:") == 0);
    EXPECT_EQ(result, "POLICY:" + std::to_string(policyCode));
}

/**
 * @tc.name: TestMakeEventId_ValidEvent_ReturnCorrectFormat
 * @tc.desc: Test MakeEventId with a valid event value returns EVENT prefix.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveApiWhitelistTest, TestMakeEventId_ValidEvent_ReturnCorrectFormat, TestSize.Level1)
{
    uint32_t managedEvent = static_cast<uint32_t>(ManagedEvent::SMS_RECEIVED);
    std::string result = SensitiveApiWhitelist::MakeEventId(managedEvent);
    EXPECT_FALSE(result.empty());
    EXPECT_TRUE(result.find("EVENT:") == 0);
    EXPECT_EQ(result, "EVENT:" + std::to_string(managedEvent));
    EXPECT_NE(result, SensitiveApiWhitelist::MakePolicyId(managedEvent));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
