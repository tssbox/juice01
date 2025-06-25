/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

module.exports.getAddress = function getAddress () {
  return async (req: Request, res: Response) => {
    const userId = req.user.id; // Use authenticated user's ID
    const addresses = await AddressModel.findAll({ where: { UserId: userId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

module.exports.getAddressById = function getAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.user.id; // Use authenticated user's ID
    const addressId = parseInt(req.params.id, 10); // Ensure the ID is an integer
    if (isNaN(addressId)) {
      return res.status(400).json({ status: 'error', data: 'Invalid address ID.' })
    }
    const address = await AddressModel.findOne({ where: { id: addressId, UserId: userId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found.' })
    }
  }
}

module.exports.delAddressById = function delAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.user.id; // Use authenticated user's ID
    const addressId = parseInt(req.params.id, 10); // Ensure the ID is an integer
    if (isNaN(addressId)) {
      return res.status(400).json({ status: 'error', data: 'Invalid address ID.' })
    }
    const address = await AddressModel.destroy({ where: { id: addressId, UserId: userId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found.' })
    }
  }
}

module.exports.updateAddressById = function updateAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.user.id; // Use authenticated user's ID
    const addressId = parseInt(req.params.id, 10); // Ensure the ID is an integer
    if (isNaN(addressId)) {
      return res.status(400).json({ status: 'error', data: 'Invalid address ID.' })
    }
    const { fullName, mobileNum, zipCode, streetAddress, city, state, country } = req.body;
    try {
      const [updated] = await AddressModel.update({
        fullName,
        mobileNum,
        zipCode,
        streetAddress,
        city,
        state,
        country
      }, {
        where: { id: addressId, UserId: userId }
      });
      if (updated) {
        const updatedAddress = await AddressModel.findOne({ where: { id: addressId, UserId: userId } });
        return res.status(200).json({ status: 'success', data: updatedAddress });
      }
      throw new Error('Address not found');
    } catch (error) {
      return res.status(500).json({ status: 'error', data: error.message });
    }
  }
}
