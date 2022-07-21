/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef COMMON_NATIVE_INCLUDE_EDM_LOG_H
#define COMMON_NATIVE_INCLUDE_EDM_LOG_H

#include "errors.h"
#include "hilog/log.h"

namespace OHOS {
namespace EDM {
static constexpr int LOG_DOMAIN_ID_EDM = 0xD001E00;
static constexpr OHOS::HiviewDFX::HiLogLabel EDM_LABEL = { LOG_CORE, LOG_DOMAIN_ID_EDM, "EDM" };
#ifndef EDMLOGD
#define EDMLOGD(...) (void)OHOS::HiviewDFX::HiLog::Debug(EDM_LABEL, __VA_ARGS__)
#endif

#ifndef EDMLOGE
#define EDMLOGE(...) (void)OHOS::HiviewDFX::HiLog::Error(EDM_LABEL, __VA_ARGS__)
#endif

#ifndef EDMLOGF
#define EDMLOGF(...) (void)OHOS::HiviewDFX::HiLog::Fatal(EDM_LABEL, __VA_ARGS__)
#endif

#ifndef EDMLOGI
#define EDMLOGI(...) (void)OHOS::HiviewDFX::HiLog::Info(EDM_LABEL, __VA_ARGS__)
#endif

#ifndef EDMLOGW
#define EDMLOGW(...) (void)OHOS::HiviewDFX::HiLog::Warn(EDM_LABEL, __VA_ARGS__)
#endif
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_EDM_LOG_H
