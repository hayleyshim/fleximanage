// flexiWAN SD-WAN software - flexiEdge, flexiManage. For more information go to https://flexiwan.com
// Copyright (C) 2019  flexiWAN Ltd.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('./cors');
const configs = require('../configs')();
const auth = require('../authenticate');
const connections = require('../websocket/Connections')();
const deviceStatus = require('../periodic/deviceStatus')();
const usersModel = require('../models/users');
const tunnelsModel = require('../models/tunnels');
const {devices:devicesModel} = require('../models/devices');
const {deviceAggregateStats} = require('../models/analytics/deviceStats');
const accountsModel = require('../models/accounts');
const {membership} = require('../models/membership');
const organizations = require('../models/organizations');
const {devices} = require('../models/devices');
const tunnels = require('../models/tunnels');
const tokens = require('../models/tokens');

/**
 * AdminRouter is allowed only if the user is marked as admin
 * Return internal information
 */
const adminRouter = express.Router();
adminRouter.use(bodyParser.json());

/**
 * TBD: Enhance admin page with:
 * Allow to have a list without url
 * Fix "no info" field and error - add as value for specific item
 * Add organizations
 * Show over all stats:
 *   - # Installed devcies -> Click break down per acct, org / user
 *   - # Accounts -> Show users per account
 *   - # Connected devices -> Click to see devices -> Show account / org / users the belongs to
 *   - Traffic sum - > Click breakdown per org
 */

adminRouter
    .route('/')
    .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
    .get(cors.corsWithOptions, auth.verifyAdmin, async (req,res,next) => {

        // Get accounts info
        let accounts = "No info";
        try {
            accounts = await accountsModel
            .aggregate([{'$count':'value'},{'$project':{'name':'accounts', 'value':1, 'url':'/accounts'}}])
            .allowDiskUse(true);
        } catch (e) {
            registeredUsers = "Error getting accounts info, error=" + e.message;
        };

        // Get users info
        let registeredUsers = "No info";
        try {
            registeredUsers = await usersModel
            .aggregate([{'$count':'value'},{'$project':{'name':'users', 'value':1, 'url':'/users'}}])
            .allowDiskUse(true);
        } catch (e) {
            registeredUsers = "Error getting registered users info, error=" + e.message;
        };

        // Get installed devices
        let registeredDevices = "No info";
        try {
            registeredDevices = await devicesModel
            .aggregate([{'$count':'value'},{'$project':{'name':'devices', 'value':1, 'url':'/devices'}}])
            .allowDiskUse(true);
        } catch (e) {
            registeredUsers = "Error getting registered devices info, error=" + e.message;
        };

        // Get total traffic
        let monthlyStats = "No info";
        try {
            monthlyStats = await deviceAggregateStats
            .aggregate([{'$project':{'month':1, orgs:{$objectToArray:"$stats.orgs" }}},
                {'$unwind':'$orgs'},
                {'$project':{'month':1,'org':'$org.k','devices':{$objectToArray:"$orgs.v.devices" }}},
                {'$unwind':'$devices'},
                {'$group':{'_id':0,'value':{'$sum':'$devices.v.bytes'}}},
                {'$project':{'_id':0,'name':'stats', 'value':1, 'url':'/stats'}}])
            .allowDiskUse(true);
        } catch (e) {
            monthlyStats = "Error getting stats info, error=" + e.message;
        };

        let result = [...accounts, ...registeredUsers, ...registeredDevices, ...monthlyStats];
        // Get connected devices
        const connDevices = connections.getAllDevices();
        result.push({'name':'connected', 'value':connDevices.length, url:'/connected'});

        return res.status(200).json(result);
    });

adminRouter
    .route('/users')
    .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
    .get(cors.corsWithOptions, auth.verifyAdmin, async (req,res,next) => {

        // Get users info
        let registeredUsers = "No info";
        try {
            registeredUsers = await usersModel
            .aggregate([{'$project':{'name':'$email', 'url':{'$concat':['/users/','$email']}}},{'$sort':{'name':1}}])
            .allowDiskUse(true);
        } catch (e) {
            registeredUsers = "Error getting registered users info, error=" + e.message;
        };

        return res.status(200).json(registeredUsers);
    });

adminRouter
    .route('/users/:userEmail')
    .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
    .get(cors.corsWithOptions, auth.verifyAdmin, async (req,res,next) => {

        // Get user info
        let result = {};
        try {
            const userInfo = await usersModel
            .aggregate([{$match:{'email': req.params.userEmail}},
                {'$lookup': {'from':"accounts",'localField':"defaultAccount",'foreignField':"_id",'as':"defaultAccount"}},
                {'$unwind': {'path':"$defaultAccount", "preserveNullAndEmptyArrays": true}},
                {'$lookup': {'from':"organizations",'localField':"defaultOrg",'foreignField':"_id",'as':"defaultOrg"}},
                {'$unwind': {'path':"$defaultOrg", "preserveNullAndEmptyArrays": true}}
            ])
            .allowDiskUse(true);

            const user = userInfo[0];
            result.email = user.email;
            result.userId = user._id;
            result.admin = user.admin;
            result.state = user.state;
            result.firstName = user.name;
            result.lastName = user.lastName;
            result.jobTitle = user.jobTitle;
            result.phone = user.phoneNumber;
            result.emailLinks = {
                verify:user.emailTokens.verify?
                    `${configs.get('UIServerURL')}/verify-account?email=${user.email}&t=${user.emailTokens.verify}`:"",
                inviteOrResetPassword:user.emailTokens.resetPassword?
                    `${configs.get('UIServerURL')}/reset-password?email=${user.email}&t=${user.emailTokens.resetPassword}`:""
            }
            result.defaultAccountName = user.defaultAccount? user.defaultAccount.name: "";
            result.defaultAccountId = user.defaultAccount? user.defaultAccount._id:"";
            result.defaultOrgName = user.defaultOrg? user.defaultOrg.name:"";
            result.defaultOrgId = user.defaultOrg? user.defaultOrg._id:null;

            // Get memberships
            result.memberships = {};
            const memInfo = await membership
            .aggregate([{'$match':{'user':user._id}},
                {'$lookup':{'from':"accounts",'localField':"account",'foreignField':"_id",'as':"account"}},
                {'$unwind':"$account"}])
            .allowDiskUse(true);

            memInfo.forEach(async (memEntry) => {
                if (!(memEntry.account._id in result.memberships)) {
                    result.memberships[memEntry.account._id] = {'name':memEntry.account.name, 'entities':[]};
                }
                let orgInfo = {'name':null};
                if (memEntry.to === 'organization') {
                    orgInfo = await organizations.find({'_id':memEntry.organization});
                }
                result.memberships[memEntry.account._id]['entities'].push({
                    'to':memEntry.to,
                    'entity':(memEntry.to==='account')?memEntry.account.name:
                        (memEntry.to==='group')?memEntry.group:
                        orgInfo[0].name,
                    'role':memEntry.role
                })
            });

            // Get defaultOrg inventories
            result.defaultOrgInventories = {};
            if (user.defaultOrg) {
                result.defaultOrgInventories.tokens = await tokens.find({'org':user.defaultOrg._id});
                result.defaultOrgInventories.devices = await devices.find({'org':user.defaultOrg._id});
                result.defaultOrgInventories.tunnels = await tunnels.find({'org':user.defaultOrg._id});
            }
        } catch (e) {
            result = [{'name':'Error getting registered users info, error=' + e.message, 'url':'/users'}];
        };

        return res.status(200).json(result);
    });

adminRouter
    .route('/*')
    // When options message received, reply origin based on whitelist
    .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
    .get(cors.corsWithOptions, auth.verifyAdmin, async (req,res,next) => {

        console.log("URL=" + req.url);

        // Get users info
        let registeredUsers = "No info";
        try {
            registeredUsers = await usersModel
            .aggregate([{'$project':{'username':1}},{'$count':'num_registered_users'}])
            .allowDiskUse(true);
        } catch (e) {
            registeredUsers = "Error getting registered users info, error=" + e.message;
        }

        // Get Installed Devices
        let installedDevices = "No info";
        try {
            installedDevices = await devicesModel
            .aggregate([{'$project':{'org':1}},
                {'$group':{'_id':{'org':'$org'},'num_devices':{'$sum':1}}},
                {'$project':{'_id':0,'org':'$_id.org','num_devices':'$num_devices'}}])
            .allowDiskUse(true);
        } catch (e) {
            installedDevices = "Error getting installed devices info, error=" + e.message;
        }

        // Get Installed Tunnels
        let installedTunnels = "No info";
        try {
            installedTunnels = await tunnelsModel
            .aggregate([{'$project':{'org':1,active:{$cond:[{$eq:['$isActive',true]},1,0]}}},
                {'$group':{'_id':{'org':'$org'},'created':{'$sum':1},'active':{'$sum':'$active'}}},
                {'$project':{'_id':0,'org':'$_id.org','created':'$created','active':'$active'}}])
            .allowDiskUse(true);
        } catch (e) {
            installedTunnels = "Error getting installed tunnels info, error=" + e.message;
        }

        // Get Monthly Stats
        let monthlyStats = "No info";
        try {
            monthlyStats = await deviceAggregateStats
            .aggregate([{'$project':{'month':1, orgs:{$objectToArray:"$stats.orgs" }}},
                {'$unwind':'$orgs'},
                {'$project':{'month':1,'org':'$org.k','devices':{$objectToArray:"$orgs.v.devices" }}},
                {'$unwind':'$devices'},
                {'$project':{'month':1,'org':1,'device':'$devices.k','bytes':'$devices.v.bytes'}},
                {'$group':{'_id':{'month':'$month'},'active_orgs':{'$addToSet':'$org'},
                    'active_devices':{'$addToSet':'$device'},'total_bytes':{'$sum':'$bytes'}}},
                {'$project':{'_id':0,'month':'$_id.month','activeOrgs':{'$size':'$active_orgs'},
                    'activeDevices':{'$size':'$active_devices'},'totalBytes':'$total_bytes'}},
                {'$sort':{'month':-1}}])
            .allowDiskUse(true);
            monthlyStats.forEach((result) => {
                result.month = (new Date(result.month)).toLocaleDateString();
                result.totalBytes = result.totalBytes.valueOf();
            });
        } catch (e) {
            monthlyStats = "Error getting bytes info, error=" + e.message;
        }

        // Return  static info from:
        let result = {...registeredUsers[0],
            'installedDevices':installedDevices,
            'installedTunnels':installedTunnels,
            'monthlyStats':monthlyStats,
            'connectedOrgs':{}
        };

        // 1. Open websocket connections and connection info
        const devices = connections.getAllDevices();
        result['numConnectedDevices']=devices.length;
        devices.forEach((device) => {
            const deviceInfo = connections.getDeviceInfo(device);
            if (result.connectedOrgs[deviceInfo.org] === undefined) result.connectedOrgs[deviceInfo.org] = [];
            result.connectedOrgs[deviceInfo.org].push({machineID:device,
                status:(deviceStatus.getDeviceStatus(device).state || 0)
                //ip:(deviceInfo.socket._sender._socket._peername.address || 'unknown'),
                //port:(deviceInfo.socket._sender._socket._peername.port || 'unknown')
            });
        });

        if (req.url === "/devices") {
            result = [
                {name:"users", value:5, url:"/users"},
                {name:"devices", value:Math.round(Math.random()*10), url:"/devices"},
                {name:"accounts", value:7, url:"/accounts"},
                {name:"connected", value:5, url:"/connected"},
            ];
        }

        if (req.url === "/users") {
            result = [
                {name:"nirbd@flexiwan.com", value:null, url:"/users/nirbd@flexiwan.com"},
                {name:"a@b.com", value:null, url:"/users/a@b.com"},
            ];
        }

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        return res.json(result);
    });

// Default exports
module.exports = adminRouter;