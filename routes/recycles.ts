/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

export const getRecycleItem = () => (req: Request, res: Response) => {
  const userId = req.user.id; // Assuming req.user is populated with the authenticated user's info
  RecycleModel.findAll({
    where: {
      id: JSON.parse(req.params.id),
      UserId: userId // Ensure the recycle item belongs to the authenticated user
    }
  }).then((Recycle) => {
    if (Recycle.length === 0) {
      return res.status(404).send('Recycle item not found or you do not have access to it.');
    }
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.status(500).send('Error fetching recycled items. Please try again')
  })
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
