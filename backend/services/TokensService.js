// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2020  flexiWAN Ltd.

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

const Service = require('./Service');

const jwt = require('jsonwebtoken');
const configs = require('../configs.js')();
const Tokens = require('../models/tokens');

class TokensService {
  /**
   * Get all Tokens
   *
   * offset Integer The number of items to skip before starting to collect the result set (optional)
   * limit Integer The numbers of items to return (optional)
   * returns List
   **/
  static async tokensGET ({ offset, limit }, { user }) {
    try {
      const result = await Tokens.find({ org: user.defaultOrg._id });

      const tokens = result.map(item => {
        return {
          _id: item.id,
          name: item.name,
          token: item.token
        };
      });

      return Service.successResponse(tokens);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Invalid input',
        e.status || 405
      );
    }
  }

  /**
   * Delete token
   *
   * id String Numeric ID of the Token to delete
   * no response value expected for this operation
   **/
  static async tokensIdDELETE ({ id }, { user }) {
    try {
      await Tokens.remove({
        _id: id,
        org: user.defaultOrg._id
      });

      return Service.successResponse();
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Invalid input',
        e.status || 405
      );
    }
  }

  static async tokensIdGET({ id }, { user }) {
    try {
      const token = await Tokens.findOne({ _id: id, org: user.defaultOrg._id });

      return Service.successResponse([token]);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Invalid input',
        e.status || 405
      );
    }
  }

  /**
   * Modify a token
   *
   * id String Numeric ID of the Token to modify
   * tokenRequest TokenRequest  (optional)
   * returns Token
   **/
  static async tokensIdPUT ({ id, tokenRequest }, { user }) {
    try {
      const result = await Tokens.findOneAndUpdate(
        { _id: id, org: user.defaultOrg._id },
        { tokenRequest },
        { upsert: false, runValidators: true, new: true });

      const token = {
        _id: result.id,
        name: result.name,
        token: result.token
      };

      return Service.successResponse(token);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Invalid input',
        e.status || 405
      );
    }
  }

  /**
   * Create new access token
   *
   * tokenRequest TokenRequest  (optional)
   * returns Token
   **/
  static async tokensPOST ({ tokenRequest }, { user }) {
    try {
      const body = jwt.sign({
        org: user.defaultOrg._id.toString(),
        account: user.defaultAccount._id
      }, configs.get('deviceTokenSecretKey'));

      const token = await Tokens.create({
        name: tokenRequest.name,
        org: user.defaultOrg._id.toString(),
        token: body
      });

      return Service.successResponse({
        _id: token.id,
        name: token.name,
        token: token.token
      });
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Invalid input',
        e.status || 405
      );
    }
  }
}

module.exports = TokensService;
