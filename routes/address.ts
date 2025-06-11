/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

module.exports.getAddress = function getAddress () {
  return async (req: Request, res: Response) => {
    const addresses = await AddressModel.findAll({ where: { UserId: req.body.UserId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

module.exports.getAddressById = function getAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

module.exports.delAddressById = function delAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

module.exports.createAddress = function createAddress () {
  return async (req: Request, res: Response) => {
    try {
      const { UserId, fullName, mobileNum, zipCode, streetAddress, city, state, country } = req.body;
      // Ensure the UserId in the request matches the authenticated user's ID
      if (req.user.id !== UserId) {
        return res.status(403).json({ status: 'error', message: 'Unauthorized access.' });
      }
      const newAddress = await AddressModel.create({
        UserId,
        fullName,
        mobileNum,
        zipCode,
        streetAddress,
        city,
        state,
        country
      });
      res.status(201).json({ status: 'success', data: newAddress });
    } catch (error) {
      res.status(500).json({ status: 'error', message: 'Failed to create address.' });
    }
  }
}
