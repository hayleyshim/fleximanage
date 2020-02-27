/* eslint-disable no-unused-vars */
const Service = require('./Service');

const Accounts = require('../models/accounts');
const Users = require('../models/users');
const { getToken } = require('../tokens');
const { getUserAccounts, orgUpdateFromNull } = require('../utils/membershipUtils');

class AccountsService {

  /**
   * Get all AccessTokens
   *
   * offset Integer The number of items to skip before starting to collect the result set (optional)
   * limit Integer The numbers of items to return (optional)
   * returns List
   **/
  static async accountsGET ({ offset, limit }, { user }) {
    try {
      const accounts = await getUserAccounts(user);
      return Service.successResponse(accounts);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Invalid input',
        e.status || 405,
      );
    }
  }

  /**
   * Retrieve account information
   *
   * id String Numeric ID of the Account to retrieve information
   * returns Account
   **/
  static async accountsIdGET({ id }, { user }) {
    try {
      const account = await Accounts.findOne({ _id: user.defaultAccount._id });
      const {
        logoFile,
        organizations,
        companySize,
        serviceType,
        numSites,
        __v,
        ...rest
      } = account.toObject();
      return Service.successResponse(rest);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Invalid input',
        e.status || 405,
      );
    }
  }

  /**
   * Modify account information
   *
   * id String Numeric ID of the Account to modify
   * accountRequest AccountRequest  (optional)
   * returns Account
   **/
  static async accountsIdPUT({ id, accountRequest }, { user }, response) {
    try {
      const account = await Accounts.findOneAndUpdate(
        { _id: id },
        { $set: accountRequest },
        { upsert: false, new: true, runValidators: true });

      // Update token
      const token = await getToken({ user }, { accountName: account.name });
      response.setHeader('Refresh-JWT', token);

      // Return organization
      const {
        logoFile,
        organizations,
        companySize,
        serviceType,
        numSites,
        __v,
        ...rest
      } = account.toObject();
      return Service.successResponse(rest);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Invalid input',
        e.status || 405,
      );
    }
  }

  /**
   * Select account
   *
   * selectAccountRequest SelectAccountRequest
   * returns Account
   **/
  static async accountsSelectPOST({ accountSelectRequest }, { user }) {
    try {
      if (!user.defaultAccount || !user.defaultAccount._id || !user._id) {
        return Service.rejectResponse(new Error('Error in selecting account'), 500);
      }

      // If current account not changed, return OK
      if (user.defaultAccount._id.toString() === accountSelectRequest.account) {
        return Service.successResponse({ _id: user.defaultAccount._id });
      }

      // Get organizations for the new account
      const updUser = await Users.findOneAndUpdate(
        // Query, use the email and account
        { _id: user._id },
        // Update account, set default org to null so the system
        // will choose an organization on login if something failed
        { defaultAccount: accountSelectRequest.account, defaultOrg: null },
        // Options
        { upsert: false, new: true }
      )
        .populate('defaultAccount');

        // Set a default organization for the new account
        user.defaultAccount = updUser.defaultAccount;
        user.defaultOrg = null;

        await orgUpdateFromNull(req, res);
        return Service.successResponse({ _id: updUser.defaultAccount._id });
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Invalid input',
        e.status || 405,
      );
    }
  }

  /**
   * Create new account
   *
   * registerAccountRequest RegisterAccountRequest  (optional)
   * returns Account
   **/
  static async accountsPOST({ registerAccountRequest }, { user }) {
    try {
      return Service.successResponse('');
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Invalid input',
        e.status || 405,
      );
    }
  }
}

module.exports = AccountsService;