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

#ifndef TEST_SERVICES_EDM_PLUGIN_MOCK_CERT_MANAGER_SDK_STUB_H
#define TEST_SERVICES_EDM_PLUGIN_MOCK_CERT_MANAGER_SDK_STUB_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// cm_type.h re-exports cm_config_type.h (CertManagerConfig / CmConfigItem) and is part of the
// public include dir of the certificate_manager innerkit, so it is reachable from the unittest.
#include "cm_type.h"

namespace OHOS {
namespace EDM {
namespace TEST {

/**
 * @brief Certificate manager SDK stub used to intercept the extern "C" entry points
 *        (CmGetCertManagerConfig / CmSetCertManagerConfig / CmFreeCertManagerConfig).
 *
 * The unittest executable defines those symbols itself, so the definitions take precedence
 * over the ones exported by libcert_manager_sdk.z.so at link time. That keeps the plugin
 * unit tests deterministic and independent from the certificate manager system ability.
 */
class CertManagerSdkStub {
public:
    /**
     * @brief Reset all stubbed state so every test case starts from a clean slate.
     */
    static void Reset();

    /**
     * @brief Set the config items that CmGetCertManagerConfig will hand back to the caller.
     * @param items key/value pairs, the order is preserved
     */
    static void SetConfigItems(const std::vector<std::pair<std::string, std::string>> &items);

    /**
     * @brief Get the config items that CmGetCertManagerConfig will hand back to the caller.
     */
    static std::vector<std::pair<std::string, std::string>> GetConfigItems();

    /**
     * @brief Set the return value of CmGetCertManagerConfig.
     * @param ret CM_SUCCESS(0) for success, any negative value for failure
     */
    static void SetGetConfigRet(int32_t ret);

    /**
     * @brief Get the return value of CmGetCertManagerConfig.
     */
    static int32_t GetGetConfigRet();

    /**
     * @brief Set the return value of CmSetCertManagerConfig.
     * @param ret CM_SUCCESS(0) for success, any negative value for failure
     */
    static void SetSetConfigRet(int32_t ret);

    /**
     * @brief Get the return value of CmSetCertManagerConfig.
     */
    static int32_t GetSetConfigRet();

    /**
     * @brief Get the return value used when the stub fails to allocate the config items.
     */
    static int32_t GetMallocFailRet();

    /**
     * @brief Record the config items captured by the last CmSetCertManagerConfig call.
     */
    static void SetSavedConfigItems(const std::vector<std::pair<std::string, std::string>> &items);

    /**
     * @brief Get the config items captured by the last CmSetCertManagerConfig call.
     */
    static std::vector<std::pair<std::string, std::string>> GetSavedConfigItems();

    /**
     * @brief Increment the CmSetCertManagerConfig call counter.
     */
    static void IncSetConfigCallCount();

    /**
     * @brief Increment the CmGetCertManagerConfig call counter.
     */
    static void IncGetConfigCallCount();

    /**
     * @brief Increment the CmFreeCertManagerConfig call counter.
     */
    static void IncFreeConfigCallCount();

    /**
     * @brief Get how many times CmSetCertManagerConfig was called.
     */
    static uint32_t GetSetConfigCallCount();

    /**
     * @brief Get how many times CmGetCertManagerConfig was called.
     */
    static uint32_t GetGetConfigCallCount();

    /**
     * @brief Get how many times CmFreeCertManagerConfig was called.
     */
    static uint32_t GetFreeConfigCallCount();
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS

extern "C" {
/**
 * @brief Stub of CmGetCertManagerConfig, intercepts the certificate manager SDK entry point.
 */
int32_t CmGetCertManagerConfig(const struct CmBlob *keysBlob, struct CertManagerConfig *config);

/**
 * @brief Stub of CmSetCertManagerConfig, intercepts the certificate manager SDK entry point.
 */
int32_t CmSetCertManagerConfig(const struct CertManagerConfig *config);

/**
 * @brief Stub of CmFreeCertManagerConfig, intercepts the certificate manager SDK entry point.
 */
void CmFreeCertManagerConfig(struct CertManagerConfig *config);
}

#endif // TEST_SERVICES_EDM_PLUGIN_MOCK_CERT_MANAGER_SDK_STUB_H
