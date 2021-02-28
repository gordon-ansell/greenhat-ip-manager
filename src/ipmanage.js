/**
 * @file        GreenHat IP Address Manager.
 * @module      IPManage
 * @author      Gordon Ansell   <contact@gordonansell.com> 
 * @copyright   Gordon Ansell, 2021.
 * @license     MIT
 */

'use strict';

const WhoIsHelper = require("./whoishelper");
const syslog = require("greenhat-util/syslog");
const path = require("path");
const fs = require("fs");
const IPList = require('./iplist');
const bftp = require("basic-ftp");

/**
 * Main manager class.
 */
class IPManage
{
    /**
     * Constructor.
     */
    constructor()
    {
        syslog.setExceptionTraces(true);

        this.args = require('minimist')(process.argv);
        this.appPath = path.dirname(this.args['_'][1]);
        this.dataPath = path.join(this.appPath, 'data');

        this.cfg = require(path.join(this.dataPath, 'config.js'));

        this.who = new WhoIsHelper();

        this.blocks = new IPList('Blocks', path.join(this.dataPath, 'blocks.json'), this.cfg, 
            this.cfg.readWorking, this.cfg.writeWorking);
        this.blocks.read();

    }

    /**
     * Run.
     */
    async run()
    {
        if (!this.args['_'][2]) {
            syslog.error("No command.");
            return;
        }
        
        let first = this.args['_'][2];

        if (this.args['test']) {
            this.test = true;
        }

        switch (first) {
            case 'lookup':
                await this.doLookup();
                break;
            case 'block':
                await this.doBlock();
                break;
            case 'unblock':
                await this.doUnblock();
                break;
            case 'blocklist':
                await this.doBlockList();
                break;
            case 'blocklistexpired':
                await this.doBlockList(1);
                break;
            case 'importblocks':
                await this.doImportBlocks();
                break;
            case 'importblocksspecial':
                await this.doImportBlocksSpecial();
                break;
            case 'expire':
                await this.doExpire();
                break;
            case 'findip':
                await this.doFindIp();
                break;
            case 'findcountry':
                await this.doFindCountry();
                break;
            case 'reasons':
                await this.doReasons();
                break;
            case 'printcsf':
                await this.doPrintCsf();
                break;
            case 'ftp':
                await this.doFtp();
                break;
            case 'rcsf':
                await this.doRcsf();
                break;
            case 'rcsfp':
                await this.doRcsf(true);
                break;
                case 'test':
                await this.doTest();
                break;
            case 'help':
                await this.doHelp();
                break;
            default:
                syslog.error("Invalid command.");
        }

        syslog.notice('='.repeat(50));
        console.log(' ');

        return 0;

    }

    /**
     * Help.
     */
    async doHelp()
    {
        if (this.args['_'][3]) {

        } else {
            console.log(`lookup [ip]`);
            console.log(`block [ip] {-p ports} {-d days} {-r reasonid|reason} {-x reasonextra}`);
            console.log(`unblock [ip] {-p ports}`);
            console.log(`blocklist`);
            console.log(`blocklistexpired`);
            console.log(`expire`);
            console.log(`findip [ip mask]`);
            console.log(`findcountry [country-code]`);
            console.log(`reasons`);
            console.log(`printcsf`);
            console.log(`ftp`);
            console.log(`rcsf`);
        }
    }

    /**
     * Restart CSF and LFD.
     */
    async doRcsf(askpass = false)
    {
        const { exec } = require("child_process");

        if (this.cfg.sudopw && !askpass) {

            exec('echo "' + this.cfg.sudopw + '" | sudo -S csf -ra', (error, stdout, stderr) => {
                if (error) {
                    syslog.error(`error: ${error.message}`);
                    return;
                }
                if (stderr) {
                    syslog.error(`stderr: ${stderr}`);
                    return;
                }
                console.log(`stdout: ${stdout}`);
            });

        } else {

            exec("sudo csf -ra", (error, stdout, stderr) => {
                if (error) {
                    syslog.error(`error: ${error.message}`);
                    return;
                }
                if (stderr) {
                    syslog.error(`stderr: ${stderr}`);
                    return;
                }
                console.log(`stdout: ${stdout}`);
            });
        }
    }

    /**
     * FTP?
     */
    async doFtp()
    {
 
        if (!this.cfg.ftp) {
            syslog.error("FTP has been requested but no definitions are present in the configs.");
            return;
        }

        let ftpSpecs = this.cfg.ftp;

        for (let test of ['host', 'user', 'password', 'source', 'dest']) {
            if (!test in ftpSpecs) {
                syslog.error(`FTP specification needs the '${test}' key.`);
                return;
            }
        }

        // Set up the FTP client.
        const client = new bftp.Client();
        if (ftpSpecs.verbose) {
            client.ftp.verbose = ftpSpecs.verbose;
        }

        // Connect.
        let dets = {
            host: ftpSpecs.host,
            user: ftpSpecs.user,
            password: ftpSpecs.password,
        }
        for (let poss of ['secure', 'port']) {
            if (ftpSpecs[poss]) {
                dets[poss] = ftpSpecs[poss];
            }
        }

        try {
            await client.access(dets)
        } catch (err) {
            syslog.error(`FTP connection error: ${err}`);
            client.close();
            return 0;
        }

        let file = path.join(this.dataPath, ftpSpecs.source);

        if (!fs.existsSync(file)) {
            syslog.error(`Source file ${file} not found.`);
            client.close();
            return;
        }

        let destFile = path.join(ftpSpecs.dest, ftpSpecs.source);

        try {
            syslog.info(`Uploading ${file} to ${destFile}`);
            await client.uploadFrom(file, destFile);
        } catch (err) {
            syslog.error(`FTP transfer error: ${err}`);
        }

        client.close();

    }

    /**
     * Print for CFS firewall.
     */
    async doPrintCsf()
    {
        let final = '';

        this.blocks.sortByIP();

        for (let item of this.blocks.items) {
            if (item.status) {
                continue;
            }
            let line = '';
            if (item.ports) {
                if (!this.cfg.ports[item.ports]) {
                    syslog.error(`No ports configured for '${item.ports}'.`);
                    return;
                }
                let ports = null;
                if (!Array.isArray(item.ports)) {
                    ports = [this.cfg.ports[item.ports].ports];
                } else {
                    ports = this.cfg.ports[item.ports].ports;
                }

                line += `d=${ports.join(',')}|s=${item.ip}`;

            } else {
                line += item.ip;
            }

            if (item.ports) {
                line += "\t"
            } else {
                line += "\t\t\t"
            }

            line += ` # ${item.country}`;

            if (item.org) {
                line += ` / ${item.org}`;
            }

            if (item.reason) {
                line += ` / ${item.reason}`;
            } else {
                line += ` / General`;
            }

            if (item.dtAdded) {
                line += ` / ${item.dtAdded}`;
            }

            let blockDays = this.blocks.getBlockDays(item);

            line += ` / ${blockDays} days`;

            let expires = new Date(item.dtAdded);
            expires.setMilliseconds(expires.getMilliseconds() + (blockDays * 86400000));

            line += ` (${expires.toISOString()})`;

            final += line + '\n';
        }

        console.log(final);
        try {
            let fp = path.join(this.dataPath, this.cfg.ftp.source);
            fs.writeFileSync(fp, final);
            syslog.notice(`Successfully wrote IP list to: ${fp}.`)
        } catch (err) {
            syslog.error(`Failed to write to '${fp}':  ${err.message}`);
        }
    }

    /**
     * List the reasons.
     */
    async doReasons()
    {
        if (!this.cfg.reasons) {
            syslog.advice('No reasons defined.')
            return;
        }

        let count = 0;
        for (let r of this.cfg.reasons) {
            console.log(`${count}: ${r}`);
            count++;
        }
    }

    /**
     * Look up an IP.
     */
    async doLookup()
    {
        if (!this.args['_'][3]) {
            syslog.error("No IP address.");
            return;
        }

        let ip = this.args['_'][3];       
        
        let resp = await this.who.lookup(ip);
        console.log(resp);
    }

    /**
     * Do a block.
     * 
     * @param   {string}    manIp       Manual IP.
     * @param   {boolean}   imp         Import?
     * @param   {string}    dtAdded     Date added.
     * @param   {number}    days        Days.
     */
    async doBlock(manIp = null, imp = false, dtAdded = null, days = null)
    {
        let ip = null; 

        if (Number.isInteger(days) && days == 0) {
            days = 999999;
        }

        if (manIp) {
            ip = manIp;
        } else {
            if (!this.args['_'][3]) {
                syslog.error("No IP address.");
                return;
            }

            ip = this.args['_'][3];
        }

        let ports = null;
        if (this.args['p']) {
            if (!this.cfg.ports[this.args['p']]) {
                syslog.error(`No ports definition for '${this.args['p']}'.`);
                return;
            } else {
                ports = this.args['p'];
            }
        }

        let extra = {
            days: null,
            country: null,
            org: null,
        }

        if (this.args['d']) {
            extra.days = this.args['d'];
        } else if (days) {
            extra.days = days;
        }

        if (this.args['r']) {
            if (Number.isInteger(this.args['r']) && this.args['r'] >= 0) {
                if (this.cfg.reasons[this.args['r']]) {
                    extra.reason = this.cfg.reasons[this.args['r']];
                } else {
                    syslog.error(`No reason with index ${this.args['r']}`);
                    return;
                }
            } else {
                extra.reason = this.args['r'];
            }
        }

        if (this.args['x']) {
            if (extra.reason) {
                extra.reason += ' - ' + this.args['x'];
            } else {
                extra.reason = this.args['x'];
            }
        }

        if (dtAdded) {
            extra.dtAdded = dtAdded;
        }

        // Look up the address.
        let who = null;
        if (ip.indexOf('/') == -1) {
            who = await this.who.lookup(ip);
        } else {
            let ipExtract = ip.substring(0, ip.indexOf('/'));
            who = await this.who.lookup(ipExtract);
        }

        if (this.cfg.lookup) {
            if (this.cfg.lookup.countryFields) {
                for (let c of this.cfg.lookup.countryFields) {
                    if (who[c]) {
                        extra.country = who[c].toUpperCase();
                        break;
                    }
                }
            }
            if (this.cfg.lookup.orgFields) {
                for (let o of this.cfg.lookup.orgFields) {
                    if (who[o] && !who[o].startsWith('***')) {
                        extra.org = who[o];
                        break;
                    }
                }
            }
        }

        if (!extra.days && this.cfg.countryBlockDays && extra.country && this.cfg.countryBlockDays[extra.country]) {
            extra.days = this.cfg.countryBlockDays[extra.country];
        }

        if (!extra.country) {
            syslog.warning(`No country found for ${ip}.`);
        }

        await this.blocks.add(ip, ports, extra, imp);

    }

    /**
     * Import a list of blocks.
     */
    async doImportBlocks()
    {
        if (!this.args['_'][3]) {
            syslog.error("No file name.");
            return;
        }

        let fp = path.join(this.dataPath, this.args['_'][3]);

        if (!fs.existsSync(fp)) {
            syslog.error(`Import file ${fp} not found.`);
            return;
        }

        let raw = fs.readFileSync(fp, 'utf-8');

        let lines = raw.split("\n");

        let count = 0;
        for (let line of lines) {
            await this.doBlock(line.trim(), true);
            count++;
        }

        this.blocks.sortByIP();
        this.blocks.write();

        syslog.notice(`Attempted to import ${count} records.`)
    }

    /**
     * Import a list of blocks.
     */
    async doImportBlocksSpecial()
    {
        if (!this.args['_'][3]) {
            syslog.error("No file name.");
            return;
        }

        let fp = path.join(this.dataPath, this.args['_'][3]);

        if (!fs.existsSync(fp)) {
            syslog.error(`Import file ${fp} not found.`);
            return;
        }

        let raw = fs.readFileSync(fp, 'utf-8');

        let lines = raw.split("\n");

        let count = 0;
        for (let line of lines) {
            let sp = line.split('#');
            let ip = null;
            if (sp[0].includes('|')) {
                let pip = sp[0].split('|');
                ip = pip[1].substr(2).trim();
            } else {
                ip = sp[0].trim();
            }

            let dtAdded = null;
            let days = 365;
            let rem = sp[1].split('/');
            //syslog.inspect(rem);
            if (rem[rem.length - 1].trim().startsWith('9999')) {
                dtAdded = new Date(rem[rem.length - 3].trim()).toISOString();
            } else {
                let expiredt = new Date(rem[rem.length - 1].trim());
                let addeddt = new Date(rem[rem.length - 3].trim());
                dtAdded = addeddt.toISOString();
                days = Math.round((expiredt - addeddt) / 86400000);
            }

            //console.log(`${ip} ${dtAdded} ${days}`);

            await this.doBlock(ip, true, dtAdded, days);
            count++;
        }

        this.blocks.sortByIP();
        this.blocks.write();

        syslog.notice(`Attempted to import ${count} records.`)
    }

    /**
     * Do an ublock.
     */
    async doUnblock()
    {
        if (!this.args['_'][3]) {
            syslog.error("No IP address.");
            return;
        }

        let ip = this.args['_'][3];

        let ports = null;
        if (this.args['p']) {
            if (!this.cfg.ports[this.args['p']]) {
                syslog.error(`No ports definition for '${this.args['p']}'.`);
                return;
            } else {
                ports = this.args['p'];
            }
        }

        await this.blocks.remove(ip, ports);

    }

    /**
     * Expire records.
     */
    async doExpire()
    {
        this.blocks.removeExpired();
    }

    /**
     * Blocklist.
     * 
     * @param   {number}    status      Record status.
     */
    async doBlockList(status = -1)
    {
        this.blocks.list(status);
    }

    /**
     * Find an IP.
     */
    async doFindIp()
    {
        if (!this.args['_'][3]) {
            syslog.error("No IP address mask.");
            return;
        }
        this.blocks.findIp(this.args['_'][3]);
    }

    /**
     * Find a country.
     */
    async doFindCountry()
    {
        if (!this.args['_'][3]) {
            syslog.error("No country for old men.");
            return;
        }
        this.blocks.findCountry(this.args['_'][3]);
    }

    /**
     * Run a test.
     */
    async doTest()
    {
        // Set of an IP list.
        this.test = new IPList('Test', null, this.cfg, true, true, false);

        //
        /*
        syslog.notice('Test 1: Adding 138.128.84.172 to list.');
        await this.test.add('138.128.84.172');
        syslog.notice('Test 1 done.');
        this.test.list();
        console.log(' ');

        syslog.notice('Test 2: Adding 138.128.84.172 to list again. It should say it is already listed.');
        await this.test.add('138.128.84.172');
        syslog.notice('Test 2 done');
        this.test.list();
        console.log(' ');

        syslog.notice('Test 3: Adding 94.181.47.232 (ports ssh) to list.');
        await this.test.add('94.181.47.232', 'ssh');
        syslog.notice('Test 3 done');
        this.test.list();
        console.log(' ');

        syslog.notice('Test 4: Adding 94.181.47.232 without ports to list. It should say it has made an item redundant.');
        await this.test.add('94.181.47.232');
        syslog.notice('Test 4 done');
        this.test.list();
        console.log(' ');

        syslog.notice('Test 5: Adding 188.166.215.0/24 CIDR to list.');
        await this.test.add('188.166.215.0/24');
        syslog.notice('Test 5 done');
        this.test.list();
        console.log(' ');

        syslog.notice('Test 6: Adding 188.166.215.2 CIDR to list. It should say it is already covered.');
        await this.test.add('188.166.215.2');
        syslog.notice('Test 6 done');
        this.test.list();
        console.log(' ');

        syslog.notice('Test 7: Adding 188.166.0.0/16 CIDR to list. It should say it has made an item redundant.');
        await this.test.add('188.166.0.0/16');
        syslog.notice('Test 5 done');
        this.test.list();
        console.log(' ');

        syslog.notice('Test 8: Adding 188.166.215.0/24 CIDR to list again. This time it should say it is already covered.');
        await this.test.add('188.166.215.0/24');
        syslog.notice('Test 8 done');
        this.test.list();
        console.log(' ');
        */

        syslog.notice('Test 9a: Adding 3.0.115.255 to list with frigged date and expiry.');
        await this.test.add('3.0.115.255', null, {dtAdded: '2021-02-21T10:27:53.441Z', days: 3});
        syslog.notice('Test 9a done');
        this.test.list();
        //
        syslog.notice('Test 9b: Expiring records.');
        await this.test.removeExpired(true);
        syslog.notice('Test 9b done');
        console.log('Live:');
        this.test.list();
        console.log('Expired:');
        this.test.list(1);
        //
        syslog.notice('Test 9c: Adding 3.0.115.255 to list again. It should reactivate expired record');
        await this.test.add('3.0.115.255');
        syslog.notice('Test 9c done');
        console.log('Live:');
        this.test.list();
        console.log('Expired:');
        this.test.list(1);

        console.log(' ');
    }
}

module.exports = IPManage;