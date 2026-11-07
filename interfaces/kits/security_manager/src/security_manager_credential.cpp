/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "security_manager_addon.h"

#include <sys/stat.h>

#include <vector>

#include "securec.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"

using namespace OHOS::EDM;

namespace {
constexpr int64_t WEAK_PIN_FILE_MAX_SIZE = 16 * 1024 * 1024; // 16M

void ClearAuthToken(std::vector<uint8_t> &authToken)
{
    if (!authToken.empty()) {
        (void)memset_s(authToken.data(), authToken.size(), 0, authToken.size());
        authToken.clear();
    }
}

OHOS::ErrCode ConvertAuthToken(napi_env env, napi_value argv, OHOS::MessageParcel &data,
    const AddonMethodSign &methodSign)
{
    std::vector<uint8_t> authToken;
    if (!ParseUint8Array(env, argv, authToken, EdmConstants::SecurityManager::MAX_AUTH_TOKEN_SIZE)) {
        EDMLOGE("Parameter authToken error");
        ClearAuthToken(authToken);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (authToken.empty()) {
        EDMLOGE("Parameter authToken is empty");
        ClearAuthToken(authToken);
        return EdmReturnErrCode::AUTH_TOKEN_INVALID;
    }
    if (authToken.size() > EdmConstants::SecurityManager::MAX_AUTH_TOKEN_SIZE) {
        EDMLOGE("Parameter authToken exceeds the maximum size");
        ClearAuthToken(authToken);
        return EdmReturnErrCode::AUTH_TOKEN_INVALID;
    }
    data.WriteUInt8Vector(authToken);
    ClearAuthToken(authToken);
    return OHOS::ERR_OK;
}

OHOS::ErrCode ConvertAllowableDuration(napi_env env, napi_value argv, OHOS::MessageParcel &data,
    const AddonMethodSign &methodSign)
{
    int64_t allowableDuration = 0;
    if (!ParseLong(env, allowableDuration, argv)) {
        EDMLOGE("Parameter allowableDuration error");
        return EdmReturnErrCode::AUTH_TOKEN_INVALID_DURATION_INVALID;
    }
    if (allowableDuration <= 0 ||
        static_cast<uint64_t>(allowableDuration) > EdmConstants::SecurityManager::MAX_ALLOWABLE_DURATION) {
        EDMLOGE("Parameter allowableDuration is out of range");
        return EdmReturnErrCode::AUTH_TOKEN_INVALID_DURATION_INVALID;
    }
    data.WriteUint64(static_cast<uint64_t>(allowableDuration));
    return OHOS::ERR_OK;
}
} // namespace

napi_value SecurityManagerAddon::GetCredentialId(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetCredentialId called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetCredentialId";
    addonMethodSign.argsType = {EdmAddonCommonType::CUSTOM, EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {ConvertAuthToken, ConvertAllowableDuration};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    addonMethodSign.errcodeType = ErrcodeType::NUMBER;
    addonMethodSign.isAsync = true;
    return AddonMethodAdapterNew(env, info, addonMethodSign, NativeGetCredentialId, NativeGetCredentialIdComplete);
}

void SecurityManagerAddon::NativeGetCredentialId(napi_env env, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    uint64_t credentialId = 0;
    asyncCallbackInfo->ret = SecurityManagerProxy::GetSecurityManagerProxy()->GetCredentialId(
        asyncCallbackInfo->data, credentialId);
    if (asyncCallbackInfo->ret == ERR_OK) {
        asyncCallbackInfo->reply.WriteUint64(credentialId);
    }
}

void SecurityManagerAddon::NativeGetCredentialIdComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        if (asyncCallbackInfo->ret == ERR_OK) {
            uint64_t credentialId = asyncCallbackInfo->reply.ReadUint64();
            napi_value result = nullptr;
            if (napi_create_bigint_uint64(env, credentialId, &result) != napi_ok) {
                EDMLOGE("NativeGetCredentialIdComplete failed to create bigint");
                napi_reject_deferred(env, asyncCallbackInfo->deferred,
                    CreateError(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, asyncCallbackInfo->errcodeType));
            } else {
                napi_resolve_deferred(env, asyncCallbackInfo->deferred, result);
            }
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred,
                CreateError(env, asyncCallbackInfo->ret, asyncCallbackInfo->errcodeType));
        }
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

napi_value SecurityManagerAddon::SetWeakPinEnable(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetWeakPinEnable called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR_BY_TYPE(env, argc >= ARGS_SIZE_ONE, "parameter count error",
        ErrcodeType::NUMBER);
    bool isEnable = false;
    ASSERT_AND_THROW_PARAM_ERROR_BY_TYPE(env, ParseBool(env, isEnable, argv[ARR_INDEX_ZERO]),
        "parameter isEnable error", ErrcodeType::NUMBER);
    int32_t fd = -1;
    if (isEnable) {
        if (argc < ARGS_SIZE_TWO) {
            napi_throw(env, CreateErrorByType(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED,
                "fd is required when isEnable is true", ErrcodeType::NUMBER));
            return nullptr;
        }
        ASSERT_AND_THROW_PARAM_ERROR_BY_TYPE(env, ParseInt(env, fd, argv[ARR_INDEX_ONE]),
            "parameter fd error", ErrcodeType::NUMBER);
        if (fd < 0) {
            napi_throw(env, CreateErrorByType(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED,
                "fd is invalid", ErrcodeType::NUMBER));
            return nullptr;
        }
        struct stat st;
        if (fstat(fd, &st) != 0) {
            napi_throw(env, CreateErrorByType(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED,
                "fd is not a valid file descriptor", ErrcodeType::NUMBER));
            return nullptr;
        }
        if (st.st_size > WEAK_PIN_FILE_MAX_SIZE) {
            napi_throw(env, CreateErrorByType(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED,
                "file size exceeds 16M", ErrcodeType::NUMBER));
            return nullptr;
        }
    }
    int32_t retCode = SecurityManagerProxy::GetSecurityManagerProxy()->SetWeakPinEnable(isEnable, fd);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode, ErrcodeType::NUMBER));
    }
    return nullptr;
}

napi_value SecurityManagerAddon::IsWeakPinEnabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsWeakPinEnabled called");
    bool result = false;
    int32_t retCode = SecurityManagerProxy::GetSecurityManagerProxy()->IsWeakPinEnabled(result);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode, ErrcodeType::NUMBER));
        return nullptr;
    }
    napi_value jsResult;
    NAPI_CALL(env, napi_get_boolean(env, result, &jsResult));
    return jsResult;
}
