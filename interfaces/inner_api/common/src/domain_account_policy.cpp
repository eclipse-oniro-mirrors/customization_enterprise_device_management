/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "domain_account_policy.h"

#include "cJSON.h"
#include "cjson_check.h"
#include "edm_log.h"
#include "parcel_macro.h"

namespace OHOS {
namespace EDM {
DomainAccountPolicy::DomainAccountPolicy()
{
    EDMLOGD("admin account policy instance is created without parameters");
}

DomainAccountPolicy::DomainAccountPolicy(int32_t authenticationValidityPeriod, int32_t passwordValidityPeriod,
    int32_t passwordExpirationNotification) : authenticationValidityPeriod(authenticationValidityPeriod),
    passwordValidityPeriod(passwordValidityPeriod), passwordExpirationNotification(passwordExpirationNotification)
{
    EDMLOGD("admin account policy instance is created with parameters");
}

DomainAccountPolicy::~DomainAccountPolicy()
{
    EDMLOGD("admin account policy instance is destroyed");
}

bool DomainAccountPolicy::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, authenticationValidityPeriod);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, passwordValidityPeriod);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, passwordExpirationNotification);
    return true;
}

bool DomainAccountPolicy::Unmarshalling(MessageParcel &parcel, DomainAccountPolicy &domainAccountPolicy)
{
    return domainAccountPolicy.ReadFromParcel(parcel);
}

bool DomainAccountPolicy::ReadFromParcel(MessageParcel &parcel)
{
    authenticationValidityPeriod = parcel.ReadInt32();
    passwordValidityPeriod = parcel.ReadInt32();
    passwordExpirationNotification = parcel.ReadInt32();
    return true;
}

bool DomainAccountPolicy::ConvertDomainAccountPolicyToJsStr(std::string &jsStr)
{
    cJSON *json = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(json, false);

    cJSON_AddNumberToObject(json, "authenticationValidityPeriod", authenticationValidityPeriod);
    cJSON_AddNumberToObject(json, "passwordMaximumAge", passwordValidityPeriod);
    cJSON_AddNumberToObject(json, "passwordExpirationNotification", passwordExpirationNotification);

    char *jsonStr = cJSON_PrintUnformatted(json);
    if (jsonStr == nullptr) {
        cJSON_Delete(json);
        return false;
    }
    jsStr = std::string(jsonStr);
    cJSON_Delete(json);
    cJSON_free(jsonStr);
    return true;
}

bool DomainAccountPolicy::JsStrToDomainAccountPolicy(std::string &jsStr, DomainAccountPolicy &domainAccountPolicy)
{
    cJSON *json = cJSON_Parse(jsStr.c_str());
    if (json == nullptr) {
        return false;
    }
    cJSON *itemAuthenticationValidityPeriod = cJSON_GetObjectItem(json, "authenticationValidityPeriod");
    cJSON *itemPasswordMaximumAge = cJSON_GetObjectItem(json, "passwordMaximumAge");
    cJSON *itemPasswordExpirationNotification = cJSON_GetObjectItem(json, "passwordExpirationNotification");

    if (!cJSON_IsNumber(itemAuthenticationValidityPeriod) || !cJSON_IsNumber(itemPasswordMaximumAge) ||
        !cJSON_IsNumber(itemPasswordExpirationNotification)) {
        cJSON_Delete(json);
        return false;
    }

    domainAccountPolicy.authenticationValidityPeriod = itemAuthenticationValidityPeriod->valueint;
    domainAccountPolicy.passwordValidityPeriod = itemPasswordMaximumAge->valueint;
    domainAccountPolicy.passwordExpirationNotification = itemPasswordExpirationNotification->valueint;
    cJSON_Delete(json);
    return true;
}

bool DomainAccountPolicy::CheckParameterValidity()
{
    return (authenticationValidityPeriod >= -1) && (passwordValidityPeriod >= -1) &&
        (passwordExpirationNotification >= 0);
}
} // namespace EDM
} // namespace OHOS