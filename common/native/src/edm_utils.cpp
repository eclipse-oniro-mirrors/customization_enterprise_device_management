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

#include "edm_utils.h"

#include <codecvt>
#include "edm_constants.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
const std::string ERROR_STRING = "error";
const std::u16string ERROR_USTRING = u"error";

ErrCode EdmUtils::ParseStringToInt(const std::string &str, int32_t &result)
{
    int64_t tmp;
    int32_t ret = EdmUtils::ParseStringToLong(str, tmp);
    result = tmp;
    return ret;
}

ErrCode EdmUtils::ParseStringToLong(const std::string &str, int64_t &result)
{
    char* end = nullptr;
    const char* p = str.c_str();
    errno = 0;
    result = strtol(p, &end, EdmConstants::DECIMAL);
    if (errno == ERANGE || end ==p || *end != '\0') {
        EDMLOGE("EdmUtils ParseStringToLong: parse str failed: %{public}s", p);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    return ERR_OK;
}

std::string EdmUtils::Utf16ToUtf8(const std::u16string &str16)
{
    if (str16 == ERROR_USTRING) {
        return ERROR_STRING;
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert(ERROR_STRING);
    std::string result = convert.to_bytes(str16);
    return result == ERROR_STRING ? "" : result;
}
} // namespace EDM
} // namespace OHOS