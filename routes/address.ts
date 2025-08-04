/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

export function getAddress () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId
    if (!userId) {
      return res.status(401).json({ status: 'error', data: 'Unauthorized access.' })
    }
    if (userId !== req.authenticatedUser.id) { // Ensure the user is authorized to access addresses
      return res.status(403).json({ status: 'error', data: 'Forbidden: You cannot access addresses for another user.' })
    }
    const addresses = await AddressModel.findAll({ where: { UserId: userId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

export function getAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId
    if (!userId) {
      return res.status(401).json({ status: 'error', data: 'Unauthorized access.' })
    }
    if (userId !== req.authenticatedUser.id) { // Ensure the user is authorized to access this address
      return res.status(403).json({ status: 'error', data: 'Forbidden: You cannot access this address.' })
    }
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: userId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found.' })
    }
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId
    if (!userId) {
      return res.status(401).json({ status: 'error', data: 'Unauthorized access.' })
    }
    if (userId !== req.authenticatedUser.id) { // Ensure the user is authorized to delete this address
      return res.status(403).json({ status: 'error', data: 'Forbidden: You cannot delete this address.' })
    }
    const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: userId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found.' })
    }
  }
}

export function createAddress () {
  return async (req: Request, res: Response) => {
    const userId = req.body.UserId
    if (!userId) {
      return res.status(401).json({ status: 'error', data: 'Unauthorized access.' })
    }
    if (userId !== req.authenticatedUser.id) { // Ensure the user is authorized to create an address
      return res.status(403).json({ status: 'error', data: 'Forbidden: You cannot create an address for another user.' })
    }
    const { fullName, mobileNum, zipCode, streetAddress, city, state, country } = req.body
    try {
      const newAddress = await AddressModel.create({
        UserId: userId,
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
      res.status(500).json({ status: 'error', data: 'Could not create address.' })
    }
  }
}
