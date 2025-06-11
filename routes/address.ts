/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

module.exports.getAddress = function getAddress () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId;
    if (typeof userId !== 'number') {
      return res.status(400).json({ status: 'error', data: 'Invalid UserId' });
    }
    const addresses = await AddressModel.findAll({ where: { UserId: userId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

module.exports.getAddressById = function getAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId;
    const addressId = req.params.id;
    if (typeof userId !== 'number' || typeof addressId !== 'string') {
      return res.status(400).json({ status: 'error', data: 'Invalid input' });
    }
    const address = await AddressModel.findOne({ where: { id: addressId, UserId: userId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found or you do not have access.' })
    }
  }
}

module.exports.delAddressById = function delAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId;
    const addressId = req.params.id;
    if (typeof userId !== 'number' || typeof addressId !== 'string') {
      return res.status(400).json({ status: 'error', data: 'Invalid input' });
    }
    const address = await AddressModel.destroy({ where: { id: addressId, UserId: userId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found or you do not have access.' })
    }
  }
}
