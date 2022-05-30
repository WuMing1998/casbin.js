import axios from 'axios';
import * as casbin from 'casbin';
import Permission from './Permission';
import { StringKV } from './types';
import * as Cache from './Cache';

interface BaseResponse {
    message: string;
    data: any;
}

interface AuthorizerArgs {
    endpoint?: string;
    cacheExpiredTime?: number;
    requestHeaders?: StringKV;
}

type Mode = 'auto' | 'cookies' | 'manual';

const Seconds = 60;

export class Authorizer {
    public mode!: Mode;
    public endpoint: string | undefined = undefined;
    public requestHeaders: StringKV | undefined = undefined;
    public permission: Permission | undefined;
    public cookieKey: string | undefined = undefined;
    public cacheExpiredTime = Seconds; // Seconds
    public user: string | undefined;
    public enforcer: casbin.Enforcer | undefined;

    /**
     *
     * @param mode "auto", "cookies" or "manual"
     * "auto": Specify the casbin server endpoint, and Casbin.js will load permission from it when the identity changes
     * "cookies": Casbin.js load the permission data from the cookie "access_perm" or the specified cookie key.
     * "manual": Load the permission mannually with "setPermission"
     * @param args
     * @param args.endpoint Casbin service endpoint, REQUIRED when mode === "auto"
     * @param args.cacheExpiredTime The expired time of local cache, Unit: seconds, Default: 60s, activated when mode === "auto"
     * @param args.cookieKey The cookie key when loading permission, activated when mode === "cookies"
     */
    constructor(mode: Mode = 'manual', args: AuthorizerArgs = {}) {
        const { endpoint, requestHeaders, cacheExpiredTime } = args;
        switch (mode) {
            case 'auto':
                if (!endpoint) {
                    throw new Error("Specify the endpoint when initializing casbin.js with mode === 'auto'");
                } else {
                    this.mode = mode;
                    this.endpoint = endpoint;
                    if (requestHeaders) this.requestHeaders = requestHeaders;
                    if (cacheExpiredTime) this.cacheExpiredTime = cacheExpiredTime;
                }
                break;
            case 'manual':
                this.mode = mode;
                break;
            case 'cookies':
                throw Error('Cookie mode not implemented.');
            default:
                throw new Error("Casbin.js mode can only be one of the 'auto', 'cookies' and 'manual'");
        }
    }

    /**
     * Get the permission.
     */
    public getPermission(): StringKV {
        if (this.permission) {
            return this.permission?.getPermissionJsonObject();
        } else {
            throw Error('Permission is not defined. Are you using manual mode and have set the permission?');
        }
    }

    public setPermission(permission: Record<string, unknown> | string): void {
        if (this.permission === undefined) {
            this.permission = new Permission();
        }
        this.permission.load(permission);
    }

    public async initEnforcer(s: string): Promise<void> {
        const obj = JSON.parse(s);
        if (!('m' in obj)) {
            throw Error('No model when init enforcer.');
        }
        const m = casbin.newModelFromString(obj['m']);
        this.enforcer = await casbin.newEnforcer(m);
        if ('p' in obj) {
            for (const sArray of obj['p']) {
                let arr = sArray as string[];
                arr = arr.map((v) => v.trim());
                const pType = arr.shift();
                if (pType === 'p') {
                    await this.enforcer.addPolicy(...arr);
                } else if (pType === 'g') {
                    await this.enforcer.addGroupingPolicy(...arr);
                }
            }
        }
    }

    /**
     * Initialize the enforcer
     */
    public async getEnforcerDataFromSvr(): Promise<string> {
        if (this.endpoint === undefined || this.endpoint === null) {
            throw Error('Endpoint is null or not specified.');
        }
        const resp = await axios.get<BaseResponse>(`${this.endpoint}?subject=${this.user}`, {
            headers: this.requestHeaders,
        });
        return resp.data.data;
    }

    /**
     * Set the user subject for the authroizer
     * @param user The current user
     */
    public async setUser(user: string): Promise<void> {
        if (this.mode === 'auto' && user !== this.user) {
            this.user = user;
            let config = Cache.loadFromLocalStorage(user);
            if (config === null) {
                config = await this.getEnforcerDataFromSvr();
                Cache.saveToLocalStorage(user, config, this.cacheExpiredTime);
            }
            await this.initEnforcer(config);
        }
    }

    public async can(action: string, object: string, domain?: string): Promise<boolean> {
        if (this.mode === 'manual') {
            return this.permission !== undefined && this.permission.check(action, object);
        } else if (this.mode === 'auto') {
            if (this.enforcer === undefined) {
                throw Error('Enforcer not initialized');
            } else if (domain === undefined) {
                return await this.enforcer.enforce(this.user, object, action);
            } else {
                return await this.enforcer.enforce(this.user, domain, object, action);
            }
        } else {
            throw Error(`Mode ${this.mode} not recognized.`);
        }
    }

    public async cannot(action: string, object: string, domain?: string): Promise<boolean> {
        return !(await this.can(action, object, domain));
    }

    public async canAll(action: string, objects: string[], domain?: string): Promise<boolean> {
        for (let i = 0; i < objects.length; ++i) {
            if (await this.cannot(action, objects[i], domain)) {
                return false;
            }
        }
        return true;
    }

    public async canAny(action: string, objects: string[], domain?: string): Promise<boolean> {
        for (let i = 0; i < objects.length; ++i) {
            if (await this.can(action, objects[i], domain)) {
                return true;
            }
        }
        return false;
    }
}
