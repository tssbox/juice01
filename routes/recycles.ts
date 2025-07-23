/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

exports.getRecycleItem = () => (req: Request, res: Response) => {
  RecycleModel.findAll({
    where: {
      id: req.params.id // Use parameterized query to prevent SQL injection
    }
  }).then((Recycle) => {
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

exports.blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}

exports.createRecycleItem = () => (req: Request, res: Response) => {
  const { UserId, AddressId, quantity, isPickup, date } = req.body;
  // Ensure that the input is validated and sanitized before using it
  if (typeof UserId !== 'number' || typeof AddressId !== 'number' || typeof quantity !== 'number' || typeof isPickup !== 'boolean' || isNaN(new Date(date).getTime())) {
    return res.status(400).send('Invalid input data. Please check your input and try again.');
  }
  RecycleModel.create({
    UserId,
    AddressId,
    quantity,
    isPickup,
    date
  }).then((recycleItem) => {
    return res.status(201).send(utils.queryResultToJson(recycleItem))
  }).catch((error: unknown) => {
    return res.status(500).send('Error creating recycle item. Please try again')
  })
}
