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

#include "cert_manager_sdk_stub.h"

#include <cstdlib>
#include <cstring>

#include "securec.h"

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t CM_SUCCESS_CODE = 0;
constexpr int32_t CM_MALLOC_FAIL_CODE = -15;

int32_t g_getConfigRet = CM_SUCCESS_CODE;
int32_t g_setConfigRet = CM_SUCCESS_CODE;
uint32_t g_getConfigCallCount = 0;
uint32_t g_setConfigCallCount = 0;
uint32_t g_freeConfigCallCount = 0;
std::vector<std::pair<std::string, std::string>> g_configItems;
std::vector<std::pair<std::string, std::string>> g_savedConfigItems;
} // namespace

void CertManagerSdkStub::Reset()
{
    g_getConfigRet = CM_SUCCESS_CODE;
    g_setConfigRet = CM_SUCCESS_CODE;
    g_getConfigCallCount = 0;
    g_setConfigCallCount = 0;
    g_freeConfigCallCount = 0;
    g_configItems.clear();
    g_savedConfigItems.clear();
}

void CertManagerSdkStub::SetConfigItems(const std::vector<std::pair<std::string, std::string>> &items)
{
    g_configItems = items;
}

std::vector<std::pair<std::string, std::string>> CertManagerSdkStub::GetConfigItems()
{
    return g_configItems;
}

void CertManagerSdkStub::SetGetConfigRet(int32_t ret)
{
    g_getConfigRet = ret;
}

int32_t CertManagerSdkStub::GetGetConfigRet()
{
    return g_getConfigRet;
}

void CertManagerSdkStub::SetSetConfigRet(int32_t ret)
{
    g_setConfigRet = ret;
}

int32_t CertManagerSdkStub::GetSetConfigRet()
{
    return g_setConfigRet;
}

int32_t CertManagerSdkStub::GetMallocFailRet()
{
    return CM_MALLOC_FAIL_CODE;
}

void CertManagerSdkStub::SetSavedConfigItems(const std::vector<std::pair<std::string, std::string>> &items)
{
    g_savedConfigItems = items;
}

std::vector<std::pair<std::string, std::string>> CertManagerSdkStub::GetSavedConfigItems()
{
    return g_savedConfigItems;
}

void CertManagerSdkStub::IncSetConfigCallCount()
{
    g_setConfigCallCount++;
}

void CertManagerSdkStub::IncGetConfigCallCount()
{
    g_getConfigCallCount++;
}

void CertManagerSdkStub::IncFreeConfigCallCount()
{
    g_freeConfigCallCount++;
}

uint32_t CertManagerSdkStub::GetSetConfigCallCount()
{
    return g_setConfigCallCount;
}

uint32_t CertManagerSdkStub::GetGetConfigCallCount()
{
    return g_getConfigCallCount;
}

uint32_t CertManagerSdkStub::GetFreeConfigCallCount()
{
    return g_freeConfigCallCount;
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS

extern "C" {
int32_t CmGetCertManagerConfig(const struct CmBlob *keysBlob, struct CertManagerConfig *config)
{
    (void)keysBlob;
    OHOS::EDM::TEST::CertManagerSdkStub::IncGetConfigCallCount();
    if (config == nullptr) {
        return OHOS::EDM::TEST::CertManagerSdkStub::GetGetConfigRet();
    }
    if (OHOS::EDM::TEST::CertManagerSdkStub::GetGetConfigRet() != 0) {
        return OHOS::EDM::TEST::CertManagerSdkStub::GetGetConfigRet();
    }

    const auto &items = OHOS::EDM::TEST::CertManagerSdkStub::GetConfigItems();
    config->count = static_cast<uint32_t>(items.size());
    config->configItems = nullptr;
    if (items.empty()) {
        return 0;
    }

    config->configItems = static_cast<struct CmConfigItem *>(calloc(items.size(), sizeof(struct CmConfigItem)));
    if (config->configItems == nullptr) {
        config->count = 0;
        return OHOS::EDM::TEST::CertManagerSdkStub::GetMallocFailRet();
    }
    for (size_t i = 0; i < items.size(); i++) {
        if (strncpy_s(config->configItems[i].key, sizeof(config->configItems[i].key),
                items[i].first.c_str(), sizeof(config->configItems[i].key) - 1) != EOK ||
            strncpy_s(config->configItems[i].value, sizeof(config->configItems[i].value),
                items[i].second.c_str(), sizeof(config->configItems[i].value) - 1) != EOK) {
            free(config->configItems);
            config->configItems = nullptr;
            config->count = 0;
            return OHOS::EDM::TEST::CertManagerSdkStub::GetMallocFailRet();
        }
    }
    return 0;
}

int32_t CmSetCertManagerConfig(const struct CertManagerConfig *config)
{
    OHOS::EDM::TEST::CertManagerSdkStub::IncSetConfigCallCount();
    std::vector<std::pair<std::string, std::string>> saved;
    if (config != nullptr && config->configItems != nullptr) {
        for (uint32_t i = 0; i < config->count; i++) {
            saved.emplace_back(std::string(config->configItems[i].key), std::string(config->configItems[i].value));
        }
    }
    OHOS::EDM::TEST::CertManagerSdkStub::SetSavedConfigItems(saved);
    return OHOS::EDM::TEST::CertManagerSdkStub::GetSetConfigRet();
}

void CmFreeCertManagerConfig(struct CertManagerConfig *config)
{
    OHOS::EDM::TEST::CertManagerSdkStub::IncFreeConfigCallCount();
    if (config == nullptr) {
        return;
    }
    free(config->configItems);
    config->configItems = nullptr;
    config->count = 0;
}
}
