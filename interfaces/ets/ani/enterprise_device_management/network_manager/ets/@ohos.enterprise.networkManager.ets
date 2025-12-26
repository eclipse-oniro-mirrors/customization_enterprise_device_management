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

import Want from '@ohos.app.ability.Want';

export default namespace networkManager {
    loadLibrary("networkManager_ani.z");

    export enum Direction {
        INPUT,
        OUTPUT,
        FORWARD
    }

    export enum Action {
        ALLOW,
        DENY,
        REJECT
    }

    export enum Protocol {
        ALL,
        TCP,
        UDP,
        ICMP
    }

    export enum LogType {
        NFLOG = 0
    }

    export interface FirewallRule {
        srcAddr?: string;
        destAddr?: string;
        srcPort?: string;
        destPort?: string;
        appUid?: string;
        direction?: Direction;
        action?: Action;
        protocol?: Protocol;
        family?: number;
        logType?: LogType;
    }

    export interface DomainFilterRule {
        domainName?: string;
        appUid?: string;
        direction?: Direction;
        action?: Action;
        family?: number;
        logType?: LogType;
    }

    native function addFirewallRule(admin: Want, firewallRule: FirewallRule): void;
    native function removeFirewallRule(admin: Want, firewallRule?: FirewallRule): void;
    native function addDomainFilterRule(admin: Want, domainFilterRule: DomainFilterRule): void;
    native function removeDomainFilterRule(admin: Want, domainFilterRule?: DomainFilterRule): void;
}
