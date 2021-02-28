/**
 * @file        GreenHat IP Address Manager.
 * @module      IPList
 * @author      Gordon Ansell   <contact@gordonansell.com> 
 * @copyright   Gordon Ansell, 2021.
 * @license     MIT
 */

'use strict';

const syslog = require("greenhat-util/syslog");
const WhoIsHelper = require("./whoishelper");
const fs = require('fs');
const path = require('path');
const { SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS } = require("constants");
const { init_streaming_mode } = require("striptags");

/**
 * IPList class.
 */
class IPList
{
    /**
     * Items.
     * @var {array}
     */
    items = [];

    /**
     * Whois helper.
     * @var {WhoIsHelper}
     */
    who = null;

    /**
     * Constructor.
     * 
     * @param   {string}    name            IP list name.
     * @param   {string}    filePath        Path to file.
     * @param   {object}    cfg             Configs.
     * @param   {boolean}   readWorking     Read working data.
     * @param   {boolean}   writeWorking    Write working data.
     * @param   {boolean}   io              Read/Write files.
     */
    constructor(name, filePath, cfg, readWorking = false, writeWorking = false, io = true)
    {
        this.name = name;
        this.filePath = filePath;
        this.cfg = cfg;
        this.readWorking = readWorking;
        this.writeWorking = writeWorking;
        this.io = io;

        this.who = new WhoIsHelper();

    }

    /**
     * Clear down the list.
     */
    clear()
    {
        this.items = [];
    }

    /**
     * Read the file.
     */
    async read()
    {
        if (this.io == false) {
            return;
        }

        this.items = [];

        try {
            if (fs.existsSync(this.filePath)) {
                let raw = fs.readFileSync(this.filePath);
                let parsed = JSON.parse(raw);
                syslog.trace('IPList:read', `Successfully read IP list from: ${this.filePath}.`)

                if (this.readWorking) {
                    this.items = parsed;
                } else {
                    for (let item of parsed) {
                        this.items.push(await this._addWorking(item))
                    }
                }
            } else {
                syslog.error(`Failed to read IP list from '${this.filePath}':  File does not exist.`);
            }
        } catch (err) {
            syslog.error(`Failed to read IP list from '${this.filePath}':  ${err.message}`);
        }

    }

    /**
     * Write the file.
     */
    async write()
    {
        if (this.io == false) {
            return;
        }

        try {
            if (this.writeWorking) {
                fs.writeFileSync(this.filePath, JSON.stringify(this.items));
            } else {
                let toWrite = [];
                for (let item of this.items) {
                    toWrite.push(this._removeWorking(item));
                }
                fs.writeFileSync(this.filePath, JSON.stringify(toWrite));
            }
            syslog.trace('IPList:read', `Successfully wrote IP list to: ${this.filePath}.`)
        } catch (err) {
            syslog.error(`Failed to write IP list to '${this.filePath}':  ${err.message}`);
        }
    }

    /**
     * See if an IP is a CIDR.
     * 
     * @param   {string}    ip  IP address to test.
     * @return  {boolean}       True if it is, else false. 
     */
    isCIDR(ip)
    {
        if (ip.indexOf('/') == -1) {
            return false;
        }
        return true;
    }

    /**
     * Check for an existing match for this record.
     * 
     * @param   {object}    item    Item to check.
     * @return  {boolean}           True if it's already blocked, else false.
     */
    async isAlreadyPresent(item)
    {
        let count = 0;
        for (let entry of this.items) {

            if (entry.status) {
                syslog.notice('status exit')
                continue;
            }

            // Simple match.
            if (item.ip == entry.ip) {
                //syslog.notice(item.ip + ' : ' + entry.ip + ' : ' + item.ports + ' : ' + entry.ports)
                if ((!item.ports && !entry.ports) || (item.ports == entry.ports) || (item.ports && !entry.ports)) {
                    let msg = `IP is already listed in the '${this.name}' list via ${entry.ip}`;
                    if (entry.ports) {
                        msg += `, ports: ${entry.ports}`;
                    }
                    msg += ` (index ${count}, ${entry.dtAdded}).`;
                    syslog.warning(msg);
                    return true;
                }
            } else { 
                //syslog.notice(`${entry.ip}: ${item.working.fromDec} >= ${entry.working.fromDec} && ${item.working.toDec} <= ${entry.working.toDec}`);
                if (item.working.fromDec >= entry.working.fromDec && item.working.toDec <= entry.working.toDec) {
                    let msg = `IP ${item.ip} is already covered in the '${this.name}' list via ${entry.ip} (index ${count}, ${entry.dtAdded})`;
                    syslog.warning(msg);
                    return true;
                }

            }

            count++;
        }

        return false;
    }

    /**
     * Check for redundancies.
     * 
     * @param   {object}    item    Item to check.
     */
    async checkRedundancies(item)
    {
        let count = 0;

        let filtered = [];

        for (let entry of this.items) {

            if (entry.status) {
                filtered.push(entry);
            }

            // Simple match.
            if (item.ip == entry.ip) {
                if (!item.ports && entry.ports) {
                    let msg = `Entry redundant via greater scope of ports on new entry ` + 
                        `[${entry.ip} (${entry.ports}) ${entry.dtAdded}]`;
                    syslog.warning(msg);
                }
            } else if (item.working.fromDec <= entry.working.fromDec && item.working.toDec >= entry.working.toDec) {
                if (item.ports == null || item.ports == entry.ports) {
                    let msg = `Entry redundant via greater scope of range on new entry ` + 
                        `[${entry.ip} ${entry.dtAdded}]`;
                    syslog.warning(msg);
                } else {
                    filtered.push(entry);
                }
            } else {
                filtered.push(entry);
            }

            count++;

        }

        this.items = filtered;

    }

    /**
     * Find an IP.
     * 
     * @param {string}  ip      IP to find.
     */
    async findIp(ip)
    {
        let count = 0;

        console.log('-'.repeat(30));

        for (let item of this.items) {
            if (item.ip.startsWith(ip)) {
                console.log(this._formatListItem(item, count));
                count++;
            }
        }

        console.log('-'.repeat(30));
    }

    /**
     * Find a country.
     * 
     * @param {string}  c       Country to find.
     */
    async findCountry(c)
    {
        let count = 0;

        console.log('-'.repeat(30));

        for (let item of this.items) {
            if (item.country == c) {
                console.log(this._formatListItem(item, count));
                count++;
            }
        }

        console.log('-'.repeat(30));
    }

    /**
     * Check expired records.
     * 
     * @param   {object}    ip      IP address.
     * @param   {string}    ports   Ports identifier.
     * @return  {number}            Record number if found, else -1.
     */
    async checkExpired(ip, ports = null)
    {
        if (this.items.length == 0) {
            return -1;
        }
        for (let index in this.items) {
            let item = this.items[index];
            if (item.status && (item.status == 1) && (ip == item.ip)) {
                if ((ports && !item.ports) || (!ports && item.ports)) {
                    continue;
                } else if ((item.ports && ports && item.ports == ports) || (!ports && !item.ports)) {
                    return index;
                }
            } 
        }

        return -1;
    }

    /**
     * Add an IP address.
     * 
     * @param   {string}    ip      IP address.
     * @param   {string}    ports   Ports identifier.
     * @param   {object}    extra   Extra data.
     * @param   {boolean}   imp     Is this an import?
     */
    async add(ip, ports = null, extra = null, imp = false)
    {
        let item = {
            ip: ip,
        }

        if (extra.dtAdded) {
            item.dtAdded = extra.dtAdded;
            delete extra.dtAdded;
        } else {
            item.dtAdded = new Date().toISOString();
        }

        if (ports != null) {
            item.ports = ports;
        }

        let pReason = -1;
        if (item.ports) {
            if (!this.cfg.ports[item.ports]) {
                syslog.error(`No ports definition found for '${item.ports}'.`);
                return;
            } else if (this.cfg.ports[item.ports].reason) {
                pReason = this.cfg.ports[item.ports].reason;
            }
        }

        if (!extra) {
            extra = [];
        }

        if (pReason != -1 && !extra.reason) {
            if (!this.cfg.reasons[pReason])  {
                syslog.error(`No reason with index ${pReason} (reason derived from ports).`);
                return;
            } else {
                extra.reason = this.cfg.reasons[pReason];
            }
        }

        if (extra) {
            for (let k of Object.keys(extra)) {
                if (extra[k] && extra[k] != null) {
                    item[k] = extra[k];
                }
            }

        }

        item = await this._addWorking(item);

        if (await this.isAlreadyPresent(item)) {
            return;
        }
        await this.checkRedundancies(item);

        let expChk = await this.checkExpired(ip, ports);

        if (expChk == -1) {
            this.items.push(item); 
            syslog.notice(`Added ${ip} to the '${this.name}' list.`);
        } else {
            let tmp = this.items[expChk];
            let suff = `Expired record created on ${tmp.dtAdded} and expired on ${tmp.dtExpired}.`
            delete this.items[expChk].status;
            delete this.items[expChk].dtExpired;
            delete this.items[expChk].days;
            for (let key in item) {
                this.items[expChk][key] = item[key];
            }
            syslog.notice(`Restored ${ip} to the '${this.name}' list from expired record. (${suff})`);    
        }

        if (!imp) {
            this.sortByIP();
            this.write();
        }
}

    /**
     * Remove an IP address.
     * 
     * @param   {string}    ip      IP address.
     * @param   {string}    ports   Ports identifier.
     */
    async remove(ip, ports = null) 
    {
        let newList = [];

        let found = false;

        for (let item of this.items) {
            if (item.status) {
                newList.push(item);
            }

            if (item.ip == ip) {
                if ((!ports && !item.ports) || (item.ports && ports == item.ports)) {
                    found = true;
                } else {
                    newList.push(item);
                }
            } else {
                newList.push(item);
            }
        }

        if (found) {
            this.items = newList;
            this.write();
            syslog.notice(`Removed ${ip} from the '${this.name}' list.`);
        } else {
            syslog.warning(`${ip} not found in the '${this.name}' list.`);
        }
    }

    /**
     * Get the block days.
     * 
     * @param   {object}    item    Item.
     * @return  {number}            Block days.
     */
    getBlockDays(item)
    {
        let blockdays = 0;
        if (this.cfg.defaultBlockDays) {
            blockdays = this.cfg.defaultBlockDays;
        }

        if (item.days) {
            blockdays = item.days;
        } else if (this.cfg.countryBlockDays && item.country && this.cfg.countryBlockDays[item.country]) {
            blockdays = this.cfg.countryBlockDays[item.country];
        } else if (item.ports && this.cfg.ports[item.ports] && this.cfg.ports[item.ports].days) {
            blockdays = this.cfg.ports[item.ports].days;
        }

        return blockdays;

    }

    /**
     * Remove expired entries.
     * 
     * @param   {boolean}   test    Is this a test?
     */
    async removeExpired(test = false)
    {
        let rem = 0;
        let newList = [];

        for (let item of this.items) {

            let blockdays = this.getBlockDays(item);

            if (blockdays == 0) {
                newList.push(item);
            } else {
                let dtRec = new Date(item.dtAdded);
                let dtNow = new Date();
                let elapsed = dtNow - dtRec;
                let blockedMilliseconds = 86400000 * blockdays;
                if (elapsed < blockedMilliseconds) {
                    newList.push(item);
                } else {
                    if (!this.cfg.expireDeletes) {
                        item.status = 1;
                        item.dtExpired = dtNow.toISOString();
                        newList.push(item);
                    }
                    rem++;
                }
            }

        }

        if (rem > 0) {
            syslog.notice(`Expired ${rem} records.`)
            this.items = newList;
            if (!test) {
                this.write();
            }
        } else {
            syslog.notice(`No records to expire.`);
        }
    }

    /**
     * List the items.
     * 
     * @param   {number}    status  Status of records to list.
     */
    async list(status = -1)
    {
        let count = 0;

        console.log('-'.repeat(30));

        this.sortByIP();

        for (let item of this.items) {
            if (status != -1 && item.status && item.status != status) {
                count++;
                continue;
            } else if (status == -1 && item.status) {
                count++;
                continue;
            }
            console.log(this._formatListItem(item, count));
            count++;
        }

        console.log('-'.repeat(30));
    }

    /**
     * Pad a string.
     */
    _pad(pad, str, padLeft) {
        if (typeof str === 'undefined') 
            return pad;
        if (padLeft) {
            return (pad + str).slice(-pad.length);
        } else {
            return (str + pad).substring(0, pad.length);
        }
    }

    /**
     * Format a list item.
     * 
     * @param   {object}    item    List item.
     * @param   {number}    count   List item number.     
     * @return  {string}            Formatted item.            
     */
    _formatListItem(item, count)
    {
        let line = `${count}: ${item.ip}`;
        if (item.ports) {
            line += ` (${item.ports})`;
        }

        let padding = Array(30).join(' ')
        line = this._pad(padding, line, false);

        line += ` # ${item.dtAdded}`;
        if (item.country) {
            line += `, ${item.country}`;
        }
        if (item.org) {
            line += `, ${item.org}`;
        }
        if (item.reason) {
            line += `, ${item.reason}`;
        }
        if (item.days) {
            line += `, ${item.days} days`;
        }

        if (!item.dtExpired) {
            let blockDays = this.getBlockDays(item);

            line += ` / ${blockDays} days`;

            let expires = new Date(item.dtAdded);
            expires.setMilliseconds(expires.getMilliseconds() + (blockDays * 86400000));

            line += ` (${expires.toISOString()})`;
        }

        if (item.dtExpired) {
            line += `, EXPIRED: ${item.dtExpired}`
        }
        if (item.status) {
            line += `, status: ${item.status} `
        }

        return line;
    }

    /**
     * Sort by IP.
     */
    sortByIP()
    {
        this.items.sort(this._sortIPCompare);
    }

    /**
     * The compare function for sorting items by IP.
     * 
     * @param   {object}    a   First item.
     * @param   {object}    b   Second item.
     */
    _sortIPCompare(a, b)
    {
        let ip1 = a.ip;
        if (ip1.indexOf('/') != -1) {
            let sp = ip1.split('/');
            ip1 = sp[0];
        }
        let ip2 = b.ip;
        if (ip2.indexOf('/') != -1) {
            let sp = ip2.split('/');
            ip2 = sp[0];
        }

        const num1 = Number(ip1.split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
        const num2 = Number(ip2.split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
        return num1 - num2;
    }

    /**
     * Sort by Date.
     */
    sortByDate()
    {
        this.items.sort(this._sortDateCompare);
    }

    /**
     * The compare function for sorting items by Date.
     * 
     * @param   {object}    a   First item.
     * @param   {object}    b   Second item.
     */
    _sortDateCompare(a, b)
    {
        return Date(a.dtAdded) - Date(b.dtAdded);
    }

    /**
     * Add working data.
     *
     * @param   {object}  item  Object to add data to.
     * @return  {object}        Updated item.
     */
    async _addWorking(item)
    {
        let working = {
            from: null,
            to: null,
            fromDec: null,
            toDec: null,
        }

        let ipUse = item.ip;
        if (ipUse.indexOf('/') == -1) {
            ipUse += "/32";
        }

        let sm = await this.who.subnetMask(ipUse);
        working.from = sm.ipLowStr;
        working.to = sm.ipHighStr;
        working.fromDec = sm.ipLow;
        working.toDec = sm.ipHigh;

        item.working = working;

        return item;
    }
    
    /**
     * Remove working data.
     *
     * @param   {object}  item  Object to remove data from.
     * @return  {object}        Updated item.
     */
    _removeWorking(item)
    {
        delete item.working;
        return item;
    }
}

module.exports = IPList;
