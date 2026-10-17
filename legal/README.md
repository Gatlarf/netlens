# Legal drafts (not yet reviewed by a lawyer)

These are **drafts written by the maintainer's assistant, not legal advice**. They are meant as a starting point for a lawyer who knows
Belgian and EU software and consumer law. Do not rely on them, and do not sell a licence under them, before they were reviewed.

* [`COMMERCIAL-LICENSE-DRAFT.md`](COMMERCIAL-LICENSE-DRAFT.md): the terms of the Small business, Enterprise and Supporter licences
  and of the free trial.
* [`CLA-DRAFT.md`](CLA-DRAFT.md): the agreement a contributor accepts so that the maintainer may also offer their contribution under
  the commercial licence.

## Questions for the lawyer

1. **Who is the licensor?** A natural person (with an enterprise number as self-employed, in a side activity) or a company (BV)?
   A company limits personal liability; ask whether starting one is worth it before the first sale.
2. **Merchant of record.** If Paddle (or similar) sells the licences, it is the seller to the customer and its terms apply to payment,
   VAT, refunds and the withdrawal right; the licensor grants the licence to the merchant, who passes it on. Check that the draft fits
   that structure, and which of its parts then belong in the merchant's checkout terms instead.
3. **Consumers vs businesses.** The Business and Enterprise licences are sold to businesses. The Supporter key is given to anybody who
   pays at least EUR 5, so also to consumers: which consumer rules apply (information duties, withdrawal for digital content, a "lifetime"
   promise)? Is "for life" defined safely as "for as long as Netlens is distributed with this licence system"?
4. **Liability cap and disclaimer.** Are the exclusions valid under Belgian law (intent, gross negligence, essential obligations)?
5. **PolyForm Noncommercial plus a commercial licence.** Is dual licensing this way sound, and is the sentence in `LICENSE` and the
   README ("commercial use needs a commercial license") clear enough about what counts as commercial (an employer using it at work, an
   MSP monitoring customers, a school)?
6. **CLA.** Is the grant wide enough to relicense a contribution, and how are moral rights handled under Belgian copyright law (they
   cannot be waived in full)? Is a click-through (a bot on GitHub pull requests) enough proof of acceptance?
7. **Personal data.** Licences carry a name and an e-mail address, kept in a private register and sent by e-mail. A short privacy
   notice is needed (legal basis, retention, processors: the merchant, the mail provider). The trial and the offline key check send
   nothing to the licensor.
8. **Trademark.** Is "Netlens" free to use as a name and logo, and should it be registered (Benelux)?
9. **Revoking or refunding** a key that is checked offline: what may the terms promise?

## What the product does, for the lawyer

Netlens runs on the customer's own server. It never reports to the licensor. A licence key is a signed file checked offline; it lets the
central Netlens take in more remote sites (1 free, 10 Small business, any number Enterprise or Supporter). Monitoring is never limited and
no data is deleted when a licence ends: sites beyond the limit are only frozen. The source code is readable (PolyForm Noncommercial 1.0.0).
