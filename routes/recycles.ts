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
      }
    })

    if (!recycleItem) {
      return res.status(404).send('Recycle item not found.')
    }

    // Check if the requesting user is authorized to access this recycle item
    const user = await UserModel.findOne({
      where: {
        id: req.body.UserId // Assuming UserId is passed in the request body
      }
    })

    if (!user || user.id !== recycleItem.UserId) {
      return res.status(403).send('You are not authorized to access this recycle item.')
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
