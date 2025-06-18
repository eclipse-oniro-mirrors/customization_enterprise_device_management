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

export default namespace adminManager {
    loadLibrary("adminManager_ani.z");

    export interface EnterpriseInfo {
        name: string;
        description: string;
    }

    export class EnterpriseInfoInner implements EnterpriseInfo {
        name: string = "";
        description: string = "";

        constructor(name: string, description: string) {
            this.name = name;
            this.description = description;
        }
    }

    native function getEnterpriseInfoSync(admin: Want): EnterpriseInfo;
    native function getSuperAdminSync(): Want;

    function getEnterpriseInfo(admin: Want): Promise<EnterpriseInfo> {
        return new Promise<EnterpriseInfo>((resolve, reject) => {
            taskpool.execute((): EnterpriseInfo => {
                return getEnterpriseInfoSync(admin);
            }).then((content: NullishType) => {
                resolve(content as EnterpriseInfo);
            }, (err: BusinessError): void => {
                reject(err);
            });
        });
    }

    function getEnterpriseInfo(admin: Want, callback: AsyncCallback<EnterpriseInfo>): void {
        taskpool.execute((): EnterpriseInfo => {
            return getEnterpriseInfoSync(admin);
        }).then((content: NullishType) => {
            callback(new BusinessError<void>(), content as EnterpriseInfo);
        }).catch((err: BusinessError) : void => {
            callback(err, new EnterpriseInfoInner("", ""));
        });
    }

    function getSuperAdmin(): Promise<Want> {
        return new Promise<Want>((resolve, reject) => {
            taskpool.execute((): Want => {
                return getSuperAdminSync();
            }).then((content: NullishType) => {
                resolve(content as Want);
            }, (err: BusinessError): void => {
                reject(err);
            });
        });
    }
}
