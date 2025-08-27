/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { reviewsCollection } from '../data/mongodb'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    challengeUtils.solveIf(
      challenges.forgedReviewChallenge,
      () => user?.data?.email !== req.body.author
    )

    try {
      const productId = req.params.id
      if (typeof productId !== 'string' || !/^[a-f\d]{24}$/i.test(productId)) {
        return res.status(400).json({ error: 'Invalid product ID format' })
      }
      // Validate and sanitize input to prevent NoSQL injection
      const message = utils.sanitizeInput(req.body.message)
      const author = utils.sanitizeInput(req.body.author)

      await reviewsCollection.insert({
        product: productId,
        message: message,
        author: author,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}