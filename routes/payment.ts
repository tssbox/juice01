/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CardModel } from '../models/card'
import { security } from '../lib/insecurity'

interface displayCard {
  UserId: number
  id: number
  fullName: string
  cardNum: string
  expMonth: number
  expYear: number
}

module.exports.getPaymentMethods = function getPaymentMethods () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const displayableCards: displayCard[] = []
    const userId = security.authenticatedUserId(req)
    if (!userId) {
      return res.status(401).json({ status: 'error', data: 'Unauthorized access.' })
    }
    const cards = await CardModel.findAll({ where: { UserId: userId } })
    cards.forEach(card => {
      const displayableCard: displayCard = {
        UserId: card.UserId,
        id: card.id,
        fullName: card.fullName,
        cardNum: '',
        expMonth: card.expMonth,
        expYear: card.expYear
      }
      const cardNumber = String(card.cardNum)
      displayableCard.cardNum = '*'.repeat(12) + cardNumber.substring(cardNumber.length - 4)
      displayableCards.push(displayableCard)
    })
    res.status(200).json({ status: 'success', data: displayableCards })
  }
}

module.exports.getPaymentMethodById = function getPaymentMethodById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const userId = security.authenticatedUserId(req)
    if (!userId) {
      return res.status(401).json({ status: 'error', data: 'Unauthorized access.' })
    }
    const card = await CardModel.findOne({ where: { id: req.params.id, UserId: userId } })
    if (card) {
      const displayableCard: displayCard = {
        UserId: card.UserId,
        id: card.id,
        fullName: card.fullName,
        cardNum: '',
        expMonth: card.expMonth,
        expYear: card.expYear
      }
      const cardNumber = String(card.cardNum)
      displayableCard.cardNum = '*'.repeat(12) + cardNumber.substring(cardNumber.length - 4)
      res.status(200).json({ status: 'success', data: displayableCard })
    } else {
      res.status(404).json({ status: 'error', data: 'Card not found or unauthorized access.' })
    }
  }
}

module.exports.delPaymentMethodById = function delPaymentMethodById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const userId = security.authenticatedUserId(req)
    if (!userId) {
      return res.status(401).json({ status: 'error', data: 'Unauthorized access.' })
    }
    const card = await CardModel.destroy({ where: { id: req.params.id, UserId: userId } })
    if (card) {
      res.status(200).json({ status: 'success', data: 'Card deleted successfully.' })
    } else {
      res.status(404).json({ status: 'error', data: 'Card not found or unauthorized access.' })
    }
  }
}
