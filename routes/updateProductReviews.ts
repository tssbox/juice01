/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    const reviewId = req.body.id;
    const message = req.body.message;

    // Validate and sanitize input
    if (typeof reviewId !== 'string' || typeof message !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }

    // Sanitize inputs to prevent NoSQL injection
    const sanitizedReviewId = reviewId.replace(/[^a-zA-Z0-9]/g, '');
    const sanitizedMessage = message.replace(/[$.]/g, '');

    db.reviewsCollection.updateOne( // Use updateOne instead of update for better specificity
      { _id: sanitizedReviewId }, // Ensure _id is sanitized
      { $set: { message: sanitizedMessage } }
    ).then(
      (result: { modifiedCount: number, matchedCount: number }) => { // Adjusted to match updateOne response
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modifiedCount > 1 }) // vuln-code-snippet hide-line
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.matchedCount > 0 && result.modifiedCount === 1 }) // Adjusted logic for updateOne
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
