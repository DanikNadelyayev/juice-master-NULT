/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function performRedirect () {
  // ВАЖЛИВО: Потрібно повернути функцію-мідлвар
  return (req: Request, res: Response, next: NextFunction) => {
    const toUrl = req.query.to as string // Отримуємо URL із запиту

    // --- БЕЗПЕЧНИЙ КОД (ALLOWLIST) ---
    const allowedDomains = ['github.com', 'explorer.dash.org', 'blockchain.info', 'etherscan.io', 'owasp.org']
    let isSafe = false
    
    // Перевірка на undefined
    if (!toUrl) {
      next(new Error('No URL provided'))
      return
    }

    // 1. Дозволяємо відносні шляхи (внутрішні сторінки сайту)
    if (toUrl.startsWith('/')) {
        isSafe = true
    } else {
      // 2. Дозволяємо тільки домени з білого списку
      try {
        if (allowedDomains.includes(new URL(toUrl).hostname)) {
            isSafe = true
        }
      } catch (e) {
        // Якщо URL некоректний, isSafe залишається false
      }
    }

    if (isSafe) {
      // (Опціонально) Логіка для челенджів
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6' })

      res.redirect(toUrl)
    } else {
      res.status(406)
      next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    }
  }
}

// Допоміжна функція (дописав кінець, щоб не було помилок)
function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}