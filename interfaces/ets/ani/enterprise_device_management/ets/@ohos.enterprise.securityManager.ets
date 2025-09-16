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

import { AsyncCallback, BusinessError } from '@ohos.base';
import Want from '@ohos.app.ability.Want';

export default namespace securityManager {
    loadLibrary("securityManager_ani.z");

    export interface PasswordPolicy {
        complexityRegex?: string;
        validityPeriod?: long;
        additionalDescription?: string;
    }

    export class PasswordPolicyInner implements PasswordPolicy {
        complexityRegex?: string = "";
        validityPeriod?: long = 0;
        additionalDescription?: string = "";
    }

    native function getPasswordPolicy(): PasswordPolicy;
}
