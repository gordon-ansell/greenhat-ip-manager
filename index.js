#!/usr/bin/env node

/**
 * @file        Application bootstrap.
 * @author      Gordon Ansell   <contact@gordonansell.com> 
 * @copyright   Gordon Ansell, 2020.
 * @license
 * 
 * Copyright (c) 2020 Gordon Ansell.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 
'use strict';

const syslog = require("greenhat-util/syslog");
const IPManage = require("./src/ipmanage");


try {

    // Unhandled promise rejections.
    process.on("unhandledRejection", (error, promise) => {
        syslog.fatal("Unhandled promise rejection.");
        syslog.exception(error, "fatal");
        process.exitCode = 1;
    });

    // Uncaught exception.
    process.on("uncaughtException", error => {
        syslog.fatal("Uncaught exception.");
        syslog.exception(error, "fatal");
        process.exitCode = 1;
    });

    // Rejection handled.
    process.on("rejectionHandled", promise => {
        syslog.warning("A promise rejection was handled asynchronously.");
        syslog.inspect(promise, "warning", "Promise object");
    });    

    /** 
    let ssg = new SSG("trace", true);
    return ssg.init().then(function() {
        return ssg.run();
    });
    */
    console.log(' ');
    syslog.notice('='.repeat(50));
    syslog.notice("GreenHat IP Manager");

    let ipm = new IPManage();
    return ipm.run();

} catch (err) {
    syslog.fatal(`Fatal error. Black hole. Call interplanetary help.`);
    syslog.exception(err, "fatal");
    process.exitCode = 1;
}