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

import hilog from '@ohos.hilog';

class EnterpriseAdminExtensionAbility {
  onAdminEnabled() {
    hilog.info('onAdminEnabled');
  }
  onAdminDisabled() {
    hilog.info('onAdminDisabled');
  }
  onBundleAdded(bundleName) {
    hilog.info('EnterpriseAdminExtensionAbility->OnBundleAdded:' + bundleName);
  }
  onBundleRemoved(bundleName) {
    hilog.info('EnterpriseAdminExtensionAbility->OnBundleRemoved:' + bundleName);
  }
  onAppStart(bundleName) {
    hilog.info('EnterpriseAdminExtensionAbility->onAppStart:' + bundleName);
  }
  onAppStop(bundleName) {
    hilog.info('EnterpriseAdminExtensionAbility->onAppStop:' + bundleName);
  }
}

export default EnterpriseAdminExtensionAbility;