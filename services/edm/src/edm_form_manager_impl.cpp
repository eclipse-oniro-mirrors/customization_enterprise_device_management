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

#include "edm_form_manager_impl.h"

#include "edm_log.h"
#include "form_mgr.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<EdmFormManagerImpl> EdmFormManagerImpl::instance_;
std::once_flag EdmFormManagerImpl::flag_;

std::shared_ptr<EdmFormManagerImpl> EdmFormManagerImpl::GetInstance()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) EdmFormManagerImpl());
        }
    });
    IEdmFormManager::iInstance_ = instance_.get();
    return instance_;
}

ErrCode EdmFormManagerImpl::RequestPublishFormCrossUser(AAFwk::Want &want, int32_t userId, int64_t &formId)
{
    return OHOS::AppExecFwk::FormMgr::GetInstance().RequestPublishFormCrossUser(want, userId, formId);
}
} // namespace EDM
} // namespace OHOS
