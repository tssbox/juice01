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
      res.status(404).json({ status: 'error', data: 'Address not found or you do not have access.' })
    }
  }
}

module.exports.delAddressById = function delAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found or you do not have access.' })
    }
  }
}

module.exports.createAddress = function createAddress () {
  return async (req: Request, res: Response) => {
    try {
      const { UserId, fullName, mobileNum, zipCode, streetAddress, city, state, country } = req.body
      const newAddress = await AddressModel.create({
        UserId,
        fullName,
        mobileNum,
        zipCode,
        streetAddress,
        city,
        state,
        country
      })
      res.status(201).json({ status: 'success', data: newAddress })
    } catch (error) {
      res.status(500).json({ status: 'error', message: 'Could not create address', error: error.message })
    }
  }
}
