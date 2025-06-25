/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

module.exports.getAddress = function getAddress () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId
    if (!userId || userId !== req.user.id) { // Ensure the user is authorized to access this data
      return res.status(403).json({ status: 'error', data: 'Unauthorized access.' })
    }
    const addresses = await AddressModel.findAll({ where: { UserId: userId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

module.exports.getAddressById = function getAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId
    if (!userId || userId !== req.user.id) { // Ensure the user is authorized to access this data
      return res.status(403).json({ status: 'error', data: 'Unauthorized access.' })
    }
    const addressId = parseInt(req.params.id, 10); // Ensure the ID is an integer
    if (isNaN(addressId)) {
      return res.status(400).json({ status: 'error', data: 'Invalid address ID.' })
    }
    const address = await AddressModel.findOne({ where: { id: addressId, UserId: userId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

module.exports.delAddressById = function delAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId
    if (!userId || userId !== req.user.id) { // Ensure the user is authorized to access this data
      return res.status(403).json({ status: 'error', data: 'Unauthorized access.' })
    }
    const addressId = parseInt(req.params.id, 10); // Ensure the ID is an integer
    if (isNaN(addressId)) {
      return res.status(400).json({ status: 'error', data: 'Invalid address ID.' })
    }
    const address = await AddressModel.destroy({ where: { id: addressId, UserId: userId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}
