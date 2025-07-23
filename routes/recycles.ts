/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'
import * as utils from '../lib/utils'
import { UserModel } from '../models/user'

exports.getRecycleItem = () => async (req: Request, res: Response) => {
  try {
    const recycleItem = await RecycleModel.findOne({
      where: {
        id: JSON.parse(req.params.id)
      },
      include: [{
        model: UserModel,
        where: { id: req.user.id }, // Ensure the recycle item belongs to the authenticated user
        attributes: [] // Do not include user attributes in the response
      }]
    })

    if (!recycleItem) {
      return res.status(404).send('Recycle item not found or you do not have access to it.')
    }

    return res.send(utils.queryResultToJson(recycleItem))
  } catch (error) {
    return res.status(500).send('Error fetching recycled items. Please try again')
  }
}

exports.blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
