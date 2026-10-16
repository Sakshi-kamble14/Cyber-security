"""
build_sample_dataset.py
-----------------------
Writes dataset/sample_urls.csv - a SMALL, HAND-WRITTEN demonstration dataset.

It is NOT a real phishing dataset and is NOT a validated benchmark. The
"phishing" URLs are made-up examples that imitate common patterns; the domains
are invented. Do not visit them. See dataset/README.md.
Label: 0 = legitimate, 1 = phishing.
"""
import csv
import os

legitimate = [
    "https://www.google.com", "https://www.wikipedia.org", "https://github.com/python/cpython",
    "https://www.python.org/downloads/", "https://docs.python.org/3/library/urllib.parse.html",
    "https://stackoverflow.com/questions/tagged/python", "https://www.bbc.co.uk/news",
    "https://www.nytimes.com/section/world", "https://en.wikipedia.org/wiki/Machine_learning",
    "https://www.microsoft.com/en-us/windows", "https://www.apple.com/iphone/",
    "https://www.amazon.com/", "https://www.linkedin.com/feed/", "https://www.reddit.com/r/learnpython/",
    "https://www.youtube.com/watch?v=abc123", "https://mail.google.com/mail/u/0/",
    "https://www.nasa.gov/missions/", "https://www.mit.edu/", "https://www.ox.ac.uk/admissions",
    "https://scikit-learn.org/stable/modules/tree.html", "https://pandas.pydata.org/docs/",
    "https://numpy.org/doc/stable/", "https://streamlit.io/", "https://www.who.int/health-topics",
    "https://www.irs.gov/forms-instructions", "https://www.usa.gov/", "https://www.nih.gov/",
    "https://www.coursera.org/learn/machine-learning", "https://www.khanacademy.org/math",
    "https://www.nptel.ac.in/courses", "https://www.iitb.ac.in/", "https://www.isro.gov.in/",
    "https://www.india.gov.in/", "https://www.wired.com/story/security-news/",
    "https://www.cloudflare.com/learning/security/", "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://www.ietf.org/standards/rfcs/", "https://www.w3.org/TR/html52/",
    "https://www.ebay.com/b/Electronics", "https://www.paypal.com/in/home",
    "https://www.dropbox.com/features", "https://zoom.us/download", "https://slack.com/intl/en-in/",
    "https://www.spotify.com/in-en/", "https://www.netflix.com/in/", "https://www.imdb.com/chart/top/",
    "https://www.theguardian.com/world", "https://www.bbc.com/news/technology-12345678",
    "https://www.cs.stanford.edu/people/faculty", "https://www.bank-of-example-learning.org/",
    "http://www.example.com/", "http://neverssl.com/", "http://www.columbia.edu/~fdc/sample.html",
    "http://info.cern.ch/", "http://www.gnu.org/licenses/gpl-3.0.html",
    "https://www.my-favourite-recipes.com/best-chocolate-cake-recipe-ever-made",
    "https://support.microsoft.com/en-us/office/get-started-with-microsoft-365-online-portal-page",
    "https://www.amazon.co.uk/gp/help/customer/display.html?nodeId=201909000",
    "https://news.ycombinator.com/item?id=123456", "https://web.archive.org/web/2020/https://example.org/",
    "https://www.ox.ac.uk/about/organisation/university-of-oxford-research-and-innovation-strategy",
    "https://login.live.com/", "https://accounts.google.com/signin", "https://www.office.com/",
    "https://www.flipkart.com/mobiles", "https://www.irctc.co.in/nget/train-search",
    "https://www.sbi.co.in/", "https://www.hdfcbank.com/personal", "https://www.icicibank.com/",
    "https://www.npr.org/sections/technology/", "https://arxiv.org/abs/1706.03762",
    "https://www.kaggle.com/datasets", "https://archive.ics.uci.edu/datasets",
    "https://www.nature.com/articles/s41586-020-2649-2",
    "https://www.sciencedirect.com/science/article/pii/S0167404820301234",
    "https://www.ted.com/talks", "https://www.python.org/dev/peps/pep-0008/",
]

phishing = [
    "http://192.168.10.25/login/secure/update.html", "http://203.0.113.45/paypal/signin.php",
    "http://198.51.100.7/bank/verify-account/index.php", "http://45.33.12.9:8080/webscr/login",
    "http://http-secure-login.example-bank-verify.com/account/update-info",
    "http://paypal-account-verification-center.secure-login-update.net/signin",
    "http://amazon-order-confirm-support.billing-update-now.com/login.php?id=88123",
    "http://www.google.com@malicious-site-demo.com/login", "http://secure.bank.com@198.51.100.99/verify",
    "http://login-microsoft-office365-verify.account-security-alert.info/auth",
    "http://apple-id-locked-restore-access.com/verify/appleid/confirm-identity",
    "http://netflix-billing-problem-update-payment.com/login", "http://sbi-online-kyc-update-verify.xyz/login.php",
    "http://hdfc-netbanking-secure-verification.top/customer/login",
    "http://icici-bank-reward-points-claim-now.site/redeem?user=1234",
    "http://www.facebook.com.security-check-login.example-phish.com/confirm",
    "http://your-package-delivery-failed.track-parcel-update.co/reschedule",
    "http://free-gift-card-winner-claim-your-prize.click/claim.php",
    "http://secure-update.account-verify.paypa1-support.com/webapps/login",
    "http://dropbox-shared-document-view.docs-secure-access.online/open",
    "http://www.irs-tax-refund-claim.gov-online-portal.info/refund/form",
    "http://117.55.200.14/~admin/images/login/office365/index.html",
    "http://10.0.0.15/cgi-bin/webscr?cmd=_login-run&dispatch=5885d80a13c0db1f",
    "http://bit-coin-wallet-recover-seed-phrase.crypto-support-help.net/restore",
    "http://account-suspended-verify-now.mail-service-alert.cc/webmail/login",
    "http://whatsapp-gold-premium-upgrade-free.download-app-now.xyz/install",
    "http://instagram-copyright-appeal-form.verify-account-help.com/appeal",
    "http://lnstagram-login.com/accounts/login", "http://paypaI-secure.com/signin",
    "http://amaz0n-prime-renewal.com/billing/update", "http://faceb00k-security.net/login.php",
    "http://secure-login.verify-your-identity-now.account-center.com/index.php?session=a8f3k2",
    "http://microsoft-support-alert-virus-detected-call-now.com/warning",
    "http://update-your-bank-details.secure-banking-portal-online.com/customer/auth/login/step1",
    "http://login.verify.account.security.update.example-phish-demo.com/signin",
    "http://www.my-bank-online-secure.com@185.199.110.153/login", "http://172.16.254.1/owa/auth/logon.aspx",
    "http://192.0.2.200/dhl/tracking/confirm.php", "http://corporate-email-password-expiry-notice.com/reset",
    "http://docusign-secure-document-review.sign-now-portal.net/view",
    "http://steam-community-free-skins-trade.gift-claim.ru/login",
    "http://job-offer-hr-department-apply-now.work-from-home-pay.info/form",
    "http://sbi-yono-account-blocked-update-pan.in-secure.xyz/update",
    "http://upi-cashback-reward-claim-now.paytm-offer.top/claim",
    "http://income-tax-refund-india-claim.gov-in-portal.cc/refund",
    "http://aadhaar-update-verify-mobile-number.uidai-help.online/verify",
    "http://electricity-bill-pending-pay-now.power-board-india.xyz/pay",
    "http://courier-delivery-fee-pending.parcel-india-track.top/pay.php",
    "http://verify-your-account.com/", "http://login-secure-update.com/",
    "http://signin-account-confirm.net/index.html", "http://secure-banking-login.org/verify",
    "http://account-update-required.info/login",
    # Phishing pages sometimes use HTTPS and short URLs too (harder cases):
    "https://secure-paypal-login.com/", "https://appleid-verify-support.com/login",
    "https://microsoft-account-recovery.net/", "https://bank-secure-signin.org/",
    "https://netflix-payment-update.com/billing", "https://amazon-security-alert.com/verify",
    "https://login-facebook-help.com/", "https://google-docs-share.net/view",
    "https://office365-login-portal.com/auth", "https://dhl-parcel-redelivery.com/pay",
    "https://www.paypal.com.account-verify-center.com/signin",
    "https://secure.login.update.bank-alert-verify.com/account/confirm?token=zx81",
    "https://www.google.com@evil-demo-site.com/",
]

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_urls.csv")
with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["url", "label"])
    for u in legitimate:
        w.writerow([u, 0])
    for u in phishing:
        w.writerow([u, 1])
print(f"Wrote {OUT}: {len(legitimate)} legitimate, {len(phishing)} phishing")
