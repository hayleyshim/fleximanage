// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2019-2020  flexiWAN Ltd.

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

// Logic to apply tunnels between devices
const configs = require('../configs')();
const tunnelsModel = require('../models/tunnels');
const tunnelIDsModel = require('../models/tunnelids');
const mongoose = require('mongoose');
const randomNum = require('../utils/random-key');

const deviceQueues = require('../utils/deviceQueue')(
  configs.get('kuePrefix'),
  configs.get('redisUrl')
);
const { routerVersionsCompatible } = require('../versioning');
const logger = require('../logging/logging')({ module: module.filename, type: 'job' });

/**
 * This function is called when adding new tunnels
 * @async
 * @param  {Array}    device    an array of the devices to be modified
 * @param  {Object}   user      User object
 * @param  {Object}   data      Additional data used by caller
 * @return {None}
 */
const applyTunnelAdd = async (devices, user, data) => {
  /**
     * Request body holds the list of devices ids to connect tunnel between
     */
  const selectedDevices = data.devices;
  logger.info('Creating tunnels between devices', {
    params: { devices: selectedDevices }
  });

  // Get details for devices to connect
  const opDevices = (devices && selectedDevices)
    ? devices.filter((device) => {
      const inSelected = selectedDevices.hasOwnProperty(device._id);
      if (inSelected) return true;
      else return false;
    }) : [];

  // For each device pair, create tunnels between WAN interfaces
  const devicesLen = opDevices.length;
  // Only allow tunnels for more than two devices
  if (devicesLen >= 2) {
    const dbTasks = [];
    const userName = user.username;
    const org = user.defaultOrg._id.toString();

    for (let idxA = 0; idxA < devicesLen - 1; idxA++) {
      for (let idxB = idxA + 1; idxB < devicesLen; idxB++) {
        const deviceA = opDevices[idxA];
        const deviceB = opDevices[idxB];

        // Tunnels are supported only between devices of the same router version
        const [verA, verB] = [deviceA.versions.router, deviceB.versions.router];
        if (!routerVersionsCompatible(verA, verB)) {
          logger.warn('Tunnel creation failed', {
            params: { reason: 'Router version mismatch', versions: { verA: verA, verB: verB } }
          });
          throw new Error('Cannot create tunnels between devices with mismatching router versions');
        }

        // Find device A WAN interfaces
        const deviceAIntfs = deviceA.interfaces.filter(intf => {
          return intf.isAssigned === true && intf.type === 'WAN';
        });

        // Find device B WAN interfaces
        const deviceBIntfs = deviceB.interfaces.filter(intf => {
          return intf.isAssigned === true && intf.type === 'WAN';
        });

        const devicesInfo = {
          deviceA: { hostname: deviceA.hostname, interface: deviceAIntfs.name },
          deviceB: { hostname: deviceB.hostname, interface: deviceBIntfs.name }
        };
        logger.debug('Connecting tunnel between devices', { params: { devicesInfo } });

        // Create a tunnel from device A to device B WAN interface
        // Create a tunnel between each WAN interface on device A to
        // each of the WAN interfaces on device B. This code should be
        // modified when adding Path labels, to create tunnels
        // between each WAN interface on device A and all of the WAN
        // interfaces on device B with the same path label
        // TBD: key exchange should be dynamic
        if (deviceAIntfs.length && deviceBIntfs.length) {
          deviceAIntfs.forEach(wanIfcA => {
            deviceBIntfs.forEach(wanIfcB => {
              logger.debug('Adding tunnel between devices', {
                params: {
                  deviceA: deviceA.hostname,
                  deviceB: deviceB.hostname,
                  interfaces: {
                    interfaceA: wanIfcA.name,
                    interfaceB: wanIfcB.name
                  }
                }
              });
              // If a tunnel already exists, skip the configuration
              // Use a copy of devices objects as promise runs later
              dbTasks.push(getTunnelPromise(userName, org,
                { ...deviceA.toObject() }, { ...deviceB.toObject() },
                { ...wanIfcA.toObject() }, { ...wanIfcB.toObject() }));
            });
          });
        } else {
          logger.info('Failed to connect tunnel between devices', {
            params: {
              deviceA: deviceA.hostname,
              deviceB: deviceB.hostname,
              reason: 'no valid WAN interfaces'
            }
          });
        }
      }
    }

    // Execute all promises
    logger.debug('Running tunnel promises', { params: { tunnels: dbTasks.length } });
    const values = await Promise.all(dbTasks);
    logger.debug('Operation completed', { params: { values: values } });
  } else {
    logger.error('At least 2 devices must be selected to create tunnels', { params: {} });
    throw new Error('At least 2 devices must be selected to create tunnels');
  }
};

/**
 * Complete tunnel add, called for each of the
 * devices that are connected by the tunnel.
 * @param  {number} jobId Kue job ID
 * @param  {Object} res   including the deviceA id, deviceB id, deviceSideConf
 * @return {void}
 */
const completeTunnelAdd = (jobId, res) => {
  logger.info('Tunnel add complete. Updating tunnel connectivity',
    { params: { result: res, jobId: jobId } });
  if (!res || !res.deviceA || !res.deviceB || !res.target || !res.username || !res.org) {
    logger.warn('Got an invalid job result', { params: { result: res, jobId: jobId } });
    return;
  }

  updateTunnelIsConnected(tunnelsModel, res.org,
    res.deviceA, res.deviceB, res.target, true)(null, (err, res) => {
    if (err) {
      logger.error('Update tunnel connectivity failed', {
        params: { jobId: jobId, reason: err.message }
      });
    }
  }
  );
};

/**
 * Error tunnel add, called for each of the
 * devices that are connected by the tunnel.
 * @param  {number} jobId Kue job ID
 * @param  {Object} res   including the deviceA id, deviceB id, deviceSideConf
 * @return {void}
 */
const errorTunnelAdd = async (jobId, res) => {
  logger.info('Tunnel add error. rollback tunnel',
    { params: { result: res, jobId: jobId } });
  if (!res || !res.deviceA || !res.deviceB || !res.target || !res.username || !res.org) {
    logger.warn('Got an invalid job result', { params: { result: res, jobId: jobId } });
    return;
  }

  tunnelsModel.findOne({ deviceA: res.deviceA, deviceB: res.deviceB, org: res.org, isActive: true })
    .then(async (tunnel) => {
      if (tunnel != null) {
        await oneTunnelDel(tunnel._id, res.username, res.org,
          (msg) => { logger.info('One tunnel del', { params: { message: msg } }); },
          () => {
            logger.info('Tunnel deleted', {
              params: {
                org: res.org,
                tunnelId: tunnel._id,
                tunnelNum: tunnel.num
              }
            });
          });
      } else {
        logger.error('errorTunnelAdd no tunnel found',
          { params: { deviceA: res.deviceA, deviceB: res.deviceB, org: res.org, isActive: true } });
      }
    }, (err) => {
      logger.error('errorTunnelAdd error', {
        params: {
          deviceA: res.deviceA,
          deviceB: res.deviceB,
          org: res.org,
          isActive: true,
          message: err.message
        }
      });
    })
    .catch((err) => {
      logger.error('errorTunnelAdd error', {
        params: {
          deviceA: res.deviceA,
          deviceB: res.deviceB,
          org: res.org,
          isActive: true,
          message: err.message
        }
      });
    });
};

/**
 * This function generates one tunnel promise including
 * all configurations for the tunnel into the device
 * @param  {string}   user         user id of the requesting user
 * @param  {string}   org          organization id the user belongs to
 * @param  {Object}   deviceA      device A details
 * @param  {Object}   deviceB      device B details
 * @param  {Object}   deviceAIntf device A tunnel interface
 * @param  {Object}   deviceBIntf device B tunnel interface
 */
const getTunnelPromise = (user, org, deviceA, deviceB,
  deviceAIntf, deviceBIntf) => {
  logger.debug('getTunnelPromise between', {
    params:
        {
          deviceA: { hostname: deviceA.hostname },
          deviceB: { hostname: deviceB.hostname }
        }
  });

  var tPromise = new Promise(function (resolve, reject) {
    tunnelsModel.find({
      $or: [
        { deviceA: deviceA._id, deviceB: deviceB._id },
        { deviceB: deviceA._id, deviceA: deviceB._id }
      ],
      isActive: true,
      org: org
    })
      .then((tunnelFound) => {
        logger.debug('Found tunnels', { params: { tunnels: tunnelFound } });

        if (tunnelFound.length === 0) { // Tunnel does not exist, need to create it
          // Get a unique tunnel number
          // Search first in deleted tunnels
          tunnelsModel.findOneAndUpdate(
            // Query
            { isActive: false, org: org },
            // Update, make sure other query doesn't find the same number
            { isActive: true },
            // Options
            { upsert: false }
          )
            .then(async (tunnelResp) => {
              logger.debug('Found a tunnel', { params: { tunnel: tunnelResp } });

              if (tunnelResp !== null) { // deleted tunnel found, use it
                const tunnelnum = tunnelResp.num;
                logger.info('Adding tunnel from deleted tunnel', { params: { tunnel: tunnelnum } });

                // Configure tunnel using this num
                const tunnelJobs = await addTunnel(user, org, tunnelnum,
                  deviceA, deviceB, deviceAIntf, deviceBIntf);

                return resolve(tunnelJobs);
              } else { // No deleted tunnel found, get a new one
                tunnelIDsModel.findOneAndUpdate(
                  // Query, allow only 15000 tunnels per organization
                  {
                    org: org,
                    nextAvailID: { $gte: 0, $lt: 15000 }
                  },
                  // Update
                  { $inc: { nextAvailID: 1 } },
                  // Options
                  { new: true, upsert: true }
                ).then(async (idResp) => {
                  const tunnelnum = idResp.nextAvailID;
                  logger.info('Adding tunnel with new ID', { params: { tunnel: tunnelnum } });

                  // Configure tunnel using this num
                  const tunnelJobs = await addTunnel(user, org, tunnelnum,
                    deviceA, deviceB, deviceAIntf, deviceBIntf);

                  return resolve(tunnelJobs);
                }, (err) => {
                  // org is a key value in the collection, upsert sometimes creates a new doc
                  // (if two upserts done at once)
                  // In this case we need to check the error and try again if such occurred
                  // See more info in:
                  // eslint-disable-next-line max-len
                  // https://stackoverflow.com/questions/37295648/mongoose-duplicate-key-error-with-upsert
                  if (err.code === 11000) {
                    logger.debug('2nd try to find tunnel ID', { params: {} });
                    tunnelIDsModel.findOneAndUpdate(
                      // Query, allow only 15000 tunnels per organization
                      {
                        org: org,
                        nextAvailID: { $gte: 0, $lt: 15000 }
                      },
                      // Update
                      { $inc: { nextAvailID: 1 } },
                      // Options
                      { new: true, upsert: true }
                    ).then(async (idResp) => {
                      const tunnelnum = idResp.nextAvailID;
                      logger.info('Adding tunnel with new ID', { params: { tunnel: tunnelnum } });
                      // Configure tunnel using this num
                      const tunnelJobs = await addTunnel(user, org, tunnelnum,
                        deviceA, deviceB, deviceAIntf, deviceBIntf);

                      return resolve(tunnelJobs);
                    }, (err) => {
                      logger.error('Tunnel ID not found (not found twice)', {
                        params: { reason: err.message }
                      });
                      reject(new Error('Tunnel ID not found'));
                    });
                  } else {
                    // Another error
                    logger.error('Tunnel ID not found (other error)', {
                      params: { reason: err.message }
                    });
                    reject(new Error('Tunnel ID not found'));
                  }
                })
                  .catch((err) => {
                    logger.error('Tunnel ID not found (general error)', {
                      params: { reason: err.message }
                    });
                    reject(new Error('Tunnel ID not found'));
                  });
              }
            }, (err) => {
              logger.error('Tunnels search error', { params: { reason: err.message } });
              reject(new Error('Tunnels search error'));
            })
            .catch((err) => {
              logger.error('Tunnels search error (general error)', {
                params: { reason: err.message }
              });
              reject(new Error('Tunnel ID not found'));
            });
        } else {
          logger.info('Tunnel found, will be checked via periodic task');
          resolve(true);
        }
      }, (err) => {
        logger.error('Tunnels find error', { params: { reason: err.message } });
        reject(new Error('Tunnels find error'));
      })
      .catch((err) => {
        logger.error('Tunnels find error (general error)', { params: { reason: err.message } });
        reject(new Error('Tunnel find error'));
      });
  });
  return tPromise;
};

/**
 * Queues the tunnel creation/deletion jobs to both
 * of the devices that are connected via the tunnel
 * @param  {boolean} isAdd        a flag indicating creation/deletion
 * @param  {string} title         title of the task
 * @param  {Object} tasksDeviceA  device A tunnel job
 * @param  {Object} tasksDeviceB  device B tunnel job
 * @param  {string} user          user id of the requesting user
 * @param  {string} org           user's organization id
 * @param  {string} devAMachineID device A host id
 * @param  {string} devBMachineID device B host id
 * @param  {string} devAOid       device A database mongodb object id
 * @param  {string} devBOid       device B database mongodb object id
 * @return {void}
 */
const queueTunnel = async (
  isAdd,
  title,
  tasksDeviceA,
  tasksDeviceB,
  user,
  org,
  devAMachineID,
  devBMachineID,
  devAOid,
  devBOid
) => {
  try {
    const devices = { deviceA: devAOid, deviceB: devBOid };
    const jobA = await deviceQueues.addJob(
      devAMachineID,
      user,
      org,
      // Data
      {
        title: title,
        tasks: tasksDeviceA
      },
      // Response data
      {
        method: isAdd ? 'tunnels' : 'deltunnels',
        data: {
          username: user,
          org: org,
          deviceA: devAOid,
          deviceB: devBOid,
          target: 'deviceAconf'
        }
      },
      // Metadata
      { priority: 'normal', attempts: 1, removeOnComplete: false },
      // Complete callback
      null
    );

    logger.info(`${isAdd ? 'Add' : 'Del'} tunnel job queued - deviceA`, {
      params: { devices: devices },
      job: jobA
    });

    const jobB = await deviceQueues.addJob(
      devBMachineID,
      user,
      org,
      // Data
      {
        title: title,
        tasks: tasksDeviceB
      },
      // Response data
      {
        method: isAdd ? 'tunnels' : 'deltunnels',
        data: {
          username: user,
          org: org,
          deviceA: devAOid,
          deviceB: devBOid,
          target: 'deviceBconf'
        }
      },
      // Metadata
      { priority: 'normal', attempts: 1, removeOnComplete: false },
      // Complete callback
      null
    );

    logger.info(`${isAdd ? 'Add' : 'Del'} tunnel job queued - deviceB`, {
      params: { devices: devices },
      job: jobB
    });

    return [jobA, jobB];
  } catch (err) {
    logger.error('Error queuing tunnel', {
      params: { deviceAId: devAMachineID, deviceBId: devBMachineID, message: err.message }
    });
    throw new Error(`Error queuing tunnel for device IDs ${devAMachineID} and ${devBMachineID}`);
  }
};

/**
 * Prepares tunnel add jobs by creating an array that contains
 * the jobs that should be queued for each of the devices connected
 * by the tunnel.
 * @param  {number} tunnelnum    tunnel id
 * @param  {Object} deviceAIntf device A tunnel interface
 * @param  {Object} deviceBIntf device B tunnel interface
 * @param  {string} devBagentVer device B version
 * @return {[{entity: string, message: string, params: Object}]} an array of tunnel-add jobs
 */
const prepareTunnelAddJob = (tunnelnum, deviceAIntf, deviceBIntf, devBagentVer) => {
  // Generate from the tunnel ID: IP A/B, MAC A/B, SA A/B, 4 IPsec Keys
  const tunnelParams = generateTunnelParams(tunnelnum);
  const tunnelKeys = generateRandomKeys();

  const tasksDeviceA = [];
  const tasksDeviceB = [];
  const paramsDeviceA = {};
  const paramsDeviceB = {};
  const paramsIpsecDeviceA = {};
  const paramsIpsecDeviceB = {};

  const paramsSaAB = {
    spi: tunnelParams.sa1,
    'crypto-key': tunnelKeys.key1,
    'integr-key': tunnelKeys.key2,
    'crypto-alg': 'aes-cbc-128',
    'integr-alg': 'sha-256-128'
  };
  const paramsSaBA = {
    spi: tunnelParams.sa2,
    'crypto-key': tunnelKeys.key3,
    'integr-key': tunnelKeys.key4,
    'crypto-alg': 'aes-cbc-128',
    'integr-alg': 'sha-256-128'
  };

  paramsDeviceA.src = deviceAIntf.IPv4;
  paramsDeviceA.dst = ((deviceBIntf.PublicIP === '') ? deviceBIntf.IPv4 : deviceBIntf.PublicIP);
  paramsDeviceA['tunnel-id'] = tunnelnum;
  paramsIpsecDeviceA['local-sa'] = paramsSaAB;
  paramsIpsecDeviceA['remote-sa'] = paramsSaBA;
  paramsDeviceA.ipsec = paramsIpsecDeviceA;
  paramsDeviceA['loopback-iface'] = {
    addr: tunnelParams.ip1 + '/31',
    mac: tunnelParams.mac1,
    mtu: 1350,
    routing: 'ospf'
  };

  paramsDeviceB.src = deviceBIntf.IPv4;
  paramsDeviceB.dst = ((deviceAIntf.PublicIP === '') ? deviceAIntf.IPv4 : deviceAIntf.PublicIP);
  paramsDeviceB['tunnel-id'] = tunnelnum;

  // const majorAgentVersion = getMajorVersion(devBagentVer);
  // if (majorAgentVersion === 0) {    // version 0.X.X
  // The following looks as a wrong config in vpp 19.01 ipsec-gre interface,
  // spi isn't configured properly for SA
  // This is also the case for version 1.X.X since we revert to ipsec-gre interface
  // Kept the comments to be fixed in later releases
  paramsIpsecDeviceB['local-sa'] = { ...paramsSaAB, spi: tunnelParams.sa2 };
  paramsIpsecDeviceB['remote-sa'] = { ...paramsSaBA, spi: tunnelParams.sa1 };
  // } else if (majorAgentVersion >= 1) {    // version 1.X.X+
  //    paramsIpsecDeviceB['local-sa'] = {...paramsSaBA};
  //    paramsIpsecDeviceB['remote-sa'] = {...paramsSaAB};
  // }

  paramsDeviceB.ipsec = paramsIpsecDeviceB;
  paramsDeviceB['loopback-iface'] = {
    addr: tunnelParams.ip2 + '/31',
    mac: tunnelParams.mac2,
    mtu: 1350,
    routing: 'ospf'
  };

  // Saving configuration for device A
  tasksDeviceA.push({ entity: 'agent', message: 'add-tunnel', params: paramsDeviceA });

  // Saving configuration for device B
  tasksDeviceB.push({ entity: 'agent', message: 'add-tunnel', params: paramsDeviceB });

  return [tasksDeviceA, tasksDeviceB];
};

/**
 * Calls the necessary APIs for creating a single tunnel
 * @param  {string}   user         user id of requesting user
 * @param  {string}   org          id of the organization of the user
 * @param  {number}   tunnelnum    id of the tunnel to be added
 * @param  {Object}   deviceA      details of device A
 * @param  {Object}   deviceB      details of device B
 * @param  {Object}   deviceAIntf device A tunnel interface
 * @param  {Object}   deviceBIntf device B tunnel interface
 * @param  {Callback} next         express next() callback
 * @param  {Callback} resolve      promise reject callback
 * @param  {Callback} reject       promise resolve callback
 * @return {void}
 */
const addTunnel = async (user, org, tunnelnum, deviceA, deviceB, deviceAIntf, deviceBIntf) => {
  const devicesInfo = {
    deviceA: { hostname: deviceA.hostname, interface: deviceAIntf.name },
    deviceB: { hostname: deviceB.hostname, interface: deviceBIntf.name }
  };

  logger.info('Adding Tunnel between devices', { params: { devices: devicesInfo } });

  await tunnelsModel.findOneAndUpdate(
    // Query, use the org and tunnel number
    {
      org: org,
      num: tunnelnum
    },
    // Update
    {
      isActive: true,
      deviceAconf: false,
      deviceBconf: false,
      deviceA: deviceA._id,
      interfaceA: deviceAIntf._id,
      deviceB: deviceB._id,
      interfaceB: deviceBIntf._id
    },
    // Options
    { upsert: true }
  );

  const { agent } = deviceB.versions;
  const [tasksDeviceA, tasksDeviceB] = prepareTunnelAddJob(
    tunnelnum,
    deviceAIntf,
    deviceBIntf,
    agent
  );

  const tunnelJobs = await queueTunnel(
    true,
    'Create tunnel between (' +
      deviceA.hostname +
      ',' +
      deviceAIntf.name +
      ') and (' +
      deviceB.hostname +
      ',' +
      deviceBIntf.name +
      ')',
    tasksDeviceA,
    tasksDeviceB,
    user,
    org,
    deviceA.machineId,
    deviceB.machineId,
    deviceA._id,
    deviceB._id
  );

  return tunnelJobs;
};

/**
 * Update tunnel device configuration
 * @param  {Object}  tunnelsModel mongoose tunnel schema
 * @param  {string}  org          organization initiated the request
 * @param  {string}  devAOid      device A mongodb object id
 * @param  {string}  devBOid      device B mongodb object id
 * @param  {string}  target       which parameter to update in the model
 * @param  {boolean} isAdd        update to configuration of true or false
 * @return {void}
 */
const updateTunnelIsConnected = (
  tunnelsModel,
  org,
  devAOid,
  devBOid,
  target,
  isAdd
) => (inp, callback) => {
  const params = {
    org: org,
    target: target,
    isAdd: isAdd,
    devices: {
      deviceA: devAOid,
      deviceB: devBOid
    }
  };
  logger.info('Updating tunnels connectivity', { params: params });
  const update = {};
  update[target] = isAdd;

  tunnelsModel
    .findOneAndUpdate(
      // Query
      { deviceA: devAOid, deviceB: devBOid, org: org },
      // Update
      update,
      // Options
      { upsert: false, new: true }
    )
    .then(
      resp => {
        if (resp != null) {
          callback(null, { ok: 1 });
        } else {
          const err = new Error('Update tunnel connected status failure');
          callback(err, false);
        }
      },
      err => {
        callback(err, false);
      }
    )
    .catch(err => {
      callback(err, false);
    });
};

/**
 * This function is called when deleting a tunnel
 * @async
 * @param  {Array}    device    an array of the devices to be modified
 * @param  {Object}   user      User object
 * @param  {Object}   data      Additional data used by caller
 * @return {None}
 */
const applyTunnelDel = async (devices, user, data) => {
  const selectedTunnels = data.tunnels;
  const tunnelIds = Object.keys(selectedTunnels);
  logger.info('Delete tunnels ', { params: { tunnels: selectedTunnels } });

  // For now assume one tunnel deletion at a time
  // Check that only one tunnel selected
  if (devices && tunnelIds.length === 1) {
    // Get tunnel data
    const tunnelID = tunnelIds[0];
    const org = user.defaultOrg._id.toString();
    const userName = user.username;

    try {
      await oneTunnelDel(tunnelID, userName, org);
    } catch (err) {
      logger.error('Attempt to delete more than one tunnel or no devices found', { params: {} });
      throw new Error('Attempt to delete more than one tunnel or no devices found');
    }
  }
};

/**
 * Deletes a single tunnel.
 * @param  {number}   tunnelID   the id of the tunnel to be deleted
 * @param  {string}   user       the user id of the requesting user
 * @param  {string}   org        the user's organization id
 * @return {void}
 */
const oneTunnelDel = async (tunnelID, user, org) => {
  const tunnelResp = await tunnelsModel.findOne({ _id: tunnelID, isActive: true, org: org })
    .populate('deviceA')
    .populate('deviceB');

  logger.debug('Delete tunnels db response', { params: { response: tunnelResp } });

  // Define devices
  const deviceA = tunnelResp.deviceA;
  const deviceB = tunnelResp.deviceB;

  // Populate interface details
  const deviceAIntf = tunnelResp.deviceA.interfaces
    .filter((ifc) => { return ifc._id.toString() === '' + tunnelResp.interfaceA; })[0];
  const deviceBIntf = tunnelResp.deviceB.interfaces
    .filter((ifc) => { return ifc._id.toString() === '' + tunnelResp.interfaceB; })[0];

  const tunnelnum = tunnelResp.num;

  const tunnelJobs = await delTunnel(user, org, tunnelnum, deviceA, deviceB,
    deviceAIntf, deviceBIntf);

  logger.info('Deleting tunnels from database');
  const resp = await tunnelsModel.findOneAndUpdate(
    // Query
    { _id: mongoose.Types.ObjectId(tunnelID), org: org },
    // Update
    { isActive: false, deviceAconf: false, deviceBconf: false },
    // Options
    { upsert: false, new: true });

  if (resp === null) throw new Error('Error deleting tunnel');

  return tunnelJobs;
};

/**
 * Called when tunnel delete jobs are finished successfully.
 * @param  {number} jobId the id of the delete tunnel job
 * @param  {Object} res   the result of the delete tunnel job
 * @return {void}
 */
const completeTunnelDel = (jobId, res) => {
  logger.info('Complete tunnel deletion job', { params: { jobId: jobId, result: res } });
};

/**
 * Prepares tunnel delete jobs by creating an array that contains
 * the jobs that should be queued for each of the devices connected
 * by the tunnel.
 * @param  {number} tunnelnum    tunnel id
 * @param  {Object} deviceAIntf device A tunnel interface
 * @param  {Object} deviceBIntf device B tunnel interface
 * @param  {string} devBagentVer device B version
 * @return {[{entity: string, message: string, params: Object}]} an array of tunnel-add jobs
 */
const prepareTunnelRemoveJob = (tunnelnum, deviceAIntf, deviceBIntf) => {
  // Generate from the tunnel num: IP A/B, MAC A/B, SA A/B
  const tunnelParams = generateTunnelParams(tunnelnum);

  const tasksDeviceA = [];
  const tasksDeviceB = [];
  const paramsDeviceA = {};
  const paramsDeviceB = {};

  paramsDeviceA.src = deviceAIntf.IPv4;
  paramsDeviceA.dst = ((deviceBIntf.PublicIP === '') ? deviceBIntf.IPv4 : deviceBIntf.PublicIP);
  paramsDeviceA['tunnel-id'] = tunnelnum;
  paramsDeviceA['loopback-iface'] = {
    addr: tunnelParams.ip1 + '/31',
    mac: tunnelParams.mac1
  };

  paramsDeviceB.src = deviceBIntf.IPv4;
  paramsDeviceB.dst = ((deviceAIntf.PublicIP === '') ? deviceAIntf.IPv4 : deviceAIntf.PublicIP);
  paramsDeviceB['tunnel-id'] = tunnelnum;
  paramsDeviceB['loopback-iface'] = {
    addr: tunnelParams.ip2 + '/31',
    mac: tunnelParams.mac2
  };

  // Saving configuration for device A
  tasksDeviceA.push({ entity: 'agent', message: 'remove-tunnel', params: paramsDeviceA });

  // Saving configuration for device B
  tasksDeviceB.push({ entity: 'agent', message: 'remove-tunnel', params: paramsDeviceB });

  return [tasksDeviceA, tasksDeviceB];
};

/**
 * Calls the necessary APIs for deleting a single tunnel
 * @param  {string}   user         user id of requesting user
 * @param  {string}   org          id of the organization of the user
 * @param  {number}   tunnelnum    id of the tunnel to be added
 * @param  {Object}   deviceA      details of device A
 * @param  {Object}   deviceB      details of device B
 * @param  {Object}   deviceAIntf device A tunnel interface
 * @param  {Object}   deviceBIntf device B tunnel interface
 * @return {void}
 */
const delTunnel = async (
  user,
  org,
  tunnelnum,
  deviceA,
  deviceB,
  deviceAIntf,
  deviceBIntf
) => {
  const [tasksDeviceA, tasksDeviceB] = prepareTunnelRemoveJob(
    tunnelnum,
    deviceAIntf,
    deviceBIntf
  );
  try {
    const tunnelJobs = await queueTunnel(
      false,
      'Delete tunnel between (' +
        deviceA.hostname +
        ',' +
        deviceAIntf.name +
        ') and (' +
        deviceB.hostname +
        ',' +
        deviceBIntf.name +
        ')',
      tasksDeviceA,
      tasksDeviceB,
      user,
      org,
      deviceA.machineId,
      deviceB.machineId,
      deviceA._id,
      deviceB._id
    );
    logger.debug('Tunnel jobs queued', { params: { jobA: tunnelJobs[0], jobB: tunnelJobs[1] } });
    return tunnelJobs;
  } catch (err) {
    logger.error('Delete tunnel error', { params: { reason: err.message } });
    throw err;
  }
};

/**
 * Generates various tunnel parameters that will
 * be used for creating the tunnel.
 * @param  {number} tunnelNum tunnel id
 * @return
 * {{
        ip1: string,
        ip2: string,
        mac1: string,
        mac2: string,
        sa1: number,
        sa2: number
    }}
 */
const generateTunnelParams = (tunnelNum) => {
  const d2h = (d) => (('00' + (+d).toString(16)).substr(-2));

  const h = (tunnelNum % 127 + 1) * 2;
  const l = Math.floor(tunnelNum / 127);
  const ip1 = '10.100.' + (+l).toString(10) + '.' + (+h).toString(10);
  const ip2 = '10.100.' + (+l).toString(10) + '.' + (+(h + 1)).toString(10);
  const mac1 = '02:00:27:fd:' + d2h(l) + ':' + d2h(h);
  const mac2 = '02:00:27:fd:' + d2h(l) + ':' + d2h(h + 1);
  const sa1 = (l * 256 + h);
  const sa2 = (l * 256 + h + 1);

  return {
    ip1: ip1,
    ip2: ip2,
    mac1: mac1,
    mac2: mac2,
    sa1: sa1,
    sa2: sa2
  };
};
/**
 * Generates random keys that will be used for tunnels creation
 * @return {{key1: number, key2: number, key3: number, key4: number}}
 */
const generateRandomKeys = () => {
  return {
    key1: randomNum(32, 16),
    key2: randomNum(32, 16),
    key3: randomNum(32, 16),
    key4: randomNum(32, 16)
  };
};

module.exports = {
  apply: {
    applyTunnelAdd: applyTunnelAdd,
    applyTunnelDel: applyTunnelDel
  },
  complete: {
    completeTunnelAdd: completeTunnelAdd,
    completeTunnelDel: completeTunnelDel
  },
  error: {
    errorTunnelAdd: errorTunnelAdd
  },
  prepareTunnelRemoveJob: prepareTunnelRemoveJob,
  prepareTunnelAddJob: prepareTunnelAddJob,
  queueTunnel: queueTunnel
};
