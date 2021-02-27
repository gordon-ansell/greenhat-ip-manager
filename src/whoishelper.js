/**
 * 
 */
const syslog = require("greenhat-util/syslog");
const ipsub = require("ip-subnet-calculator");
const deasync = require("deasync");
const got = require("got");
const striptags = require("striptags");
const ipsnc = require("ip-subnet-calculator");

class WhoIsHelper
{
    /**
     * Constructor.
     */
    constructor()
    {
    }

    /**
     * IP Decimal.
     */
    async toDec(ip)
    {
        return ipsnc.toDecimal(ip);
    }

    /**
     * Subnet mask.
     */
    async subnetMask(ip)
    {
        if (ip.indexOf("/") == -1) {
            ip += '/32';
        }
        let sp = ip.split("/");
        let op = await ipsnc.calculateSubnetMask(sp[0], sp[1]);
        return op;
    }

    /**
     * Whois
     */
    async lookup(ip) 
    {
        let ret = null;

        try {
            const response = await got("http://ga1964.com/lookup.php?ip=" + ip);
            ret = response.body;
        } catch (err) {
            syslog.error(`Could not look up whois data for ${ip}, error: ${err.message}.`);
        }

        return this._formatOp(ret);    
    }

    /**
     * Format output.
     */
    _formatOp(op)
    {
        let ret = {};

        op = striptags(op);

        for (let line of op.split("\n")) {
            if (line.startsWith('#')) {
                continue;
            }
            if (line.startsWith('Comment:')) {
                continue;
            }
            if (line.trim() == '') {
                continue;
            }

            let ind = line.indexOf(':');
            let key = line.substring(0, ind);
            let val = line.substring(ind + 1);

            ret[key] = val.trim();
        }

        let range = null;

        if (ret['NetRange']) {
            range = ret['NetRange'];
        } else if (ret['inetnum']) {
            range = ret['inetnum'];
        }

        if (range) {
            if (range.indexOf('-') != -1) {
                let sp = range.split('-');
                ret.NetLow = sp[0].trim();
                ret.NetHigh = sp[1].trim();
            } else if (range.indexOf('/') != -1) {
                let sp = range.split('/');
                let sm = ipsnc.calculateSubnetMask(sp[0], sp[1]);
                ret.NetLow = sm.ipLowStr;
                ret.NetHigh = sm.ipHighStr;
            } else {
                syslog.inspect(sp);
                syslog.error(`Problem extracting range for lookup output.`);
                syslog.inspect(ret);
                return;
            }

            ret['IPCalcs'] = ipsnc.calculate(ret.NetLow, ret.NetHigh);
            let cidrs = [];
            for (let item of ret['IPCalcs']) {
                cidrs.push(item.ipLowStr + '/' + item.prefixSize);
            }
            ret.CIDRs = cidrs;
        }

        return ret;
    }
}

module.exports = WhoIsHelper;