"""
python manage.py seed_demo          -> fills the database with realistic demo data
python manage.py seed_demo --reset  -> wipes reports/users first

All phone numbers use the fictional 555-01XX range and all names/domains are made up.
"""
import io
import random
import textwrap
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import Profile
from reports.models import Comment, Evidence, Report, ScamType, SearchLog, Vote

PASSWORD = 'scamshield123'

TYPES = [
    ('Job scam', '💼', 'Fake job offers that ask you to pay for training, equipment, or deposit cheques.',
     'Real employers never ask you to pay to start\nInterviews only on Telegram or WhatsApp are a red flag\nPay far above market for "no experience" is bait\nNever deposit a cheque and send part of it back'),
    ('Rental scam', '🏠', 'Listings for units that do not exist or are not the poster\'s to rent.',
     'Never pay a deposit before viewing in person\n"I\'m out of the country" landlords are a classic script\nReverse-image search the listing photos\nCheck the address on a map and the owner on the land registry'),
    ('CRA / government', '🏛️', 'Callers or texts pretending to be the CRA, IRCC, RCMP or Service Canada.',
     'The CRA never demands gift cards or crypto\nGovernment agencies don\'t threaten arrest by text\nHang up and call the number on canada.ca yourself\nYour SIN is never "suspended"'),
    ('Phishing', '🎣', 'Fake login pages and emails that steal passwords and card numbers.',
     'Check the exact domain before typing a password\nLook-alike spellings (paypa1, rnicrosoft) are fakes\nGo to the site directly instead of clicking the link'),
    ('Online shopping', '🛍️', 'Fake stores and marketplace sellers who take payment and ship nothing.',
     'Prices 70% below retail are a warning\nPay with a credit card for chargeback protection\nSearch the store name + "scam" before buying'),
    ('Bank & e-transfer', '🏦', 'Fake bank alerts, e-transfer deposit links and "security team" calls.',
     'Your bank will never ask for a one-time code\nInterac deposits never require you to log in on a strange site\nCall the number on the back of your card'),
    ('Investment / crypto', '📈', 'Crypto "mentors", fake trading platforms, and romance-investment scams.',
     'Guaranteed returns do not exist\nIf you can deposit but not withdraw, it\'s a scam\nStrangers who befriend you then talk crypto are scammers'),
    ('Tech support', '💻', 'Pop-ups and callers claiming your computer is infected.',
     'Microsoft and Apple never cold-call you\nNever let a stranger remote into your computer\nClose the browser tab; pop-ups can\'t infect you on their own'),
    ('Delivery / package', '📦', 'Texts about missed deliveries or customs fees with a payment link.',
     'Canada Post texts never ask for card details\nTrack packages only on the carrier\'s real website'),
    ('Family emergency', '🆘', 'Callers pretending a relative is in jail or hospital and needs money now.',
     'Hang up and call your relative directly\nAgree on a family code word\nBail is never paid in cash to a courier'),
]

USERS = [
    ('demo', 'Toronto', 'Demo account for the presentation'),
    ('uday', 'Toronto', 'Team lead, Group 11'), ('rabiya', 'Mississauga', 'Models & DB'),
    ('nancy', 'Brampton', 'Templates & UI'), ('rishi', 'Toronto', 'Forms & uploads'), ('haya', 'Oakville', 'Search & sessions'),
    ('maya_k', 'Waterloo', ''), ('jordan.t', 'Ottawa', 'Grad student'), ('priya_s', 'Hamilton', ''),
    ('liam_w', 'Toronto', ''), ('sofia.r', 'London', 'Newcomer helping newcomers'), ('ahmed.h', 'Scarborough', ''),
    ('chloe.b', 'Kingston', ''), ('daniel_o', 'Markham', ''), ('emma.l', 'Toronto', ''), ('noah_p', 'Guelph', ''),
]

# (title, identifier, type index, channel, amount, days_ago, scam_votes, safe_votes, author, description, evidence lines)
REPORTS = [
    ('Fake job offer: $45/hr data entry, asked for $200 training kit', '(437) 555-0142', 0, 'text', 200, 3, 13, 1, 'maya_k',
     'Got a text saying they found my resume on Indeed. Offered $45/hr for data entry, no experience needed. '
     'Interview was on Telegram. After "hiring" me they said I must pay $200 for a training kit by e-transfer '
     'and they would reimburse it with my first paycheque. I paid and they blocked me.',
     [('them', 'Hi! We found your resume on Indeed. Remote data entry, $45/hr, no experience needed. Interested?'),
      ('me', 'Yes, what are the next steps?'),
      ('them', 'Great! Interview is on Telegram. Before starting you must pay $200 for the training kit by e-transfer. Reply within 24 hours!')]),
    ('Same number, now "personal assistant" job with cheque deposit', '437.555.0142', 0, 'text', 0, 9, 6, 0, 'jordan.t',
     'Different job title, same number. This time they wanted me to deposit a $2,400 cheque and send $1,900 to '
     'their "equipment supplier" by e-transfer. Classic overpayment scam. Didn\'t do it.', None),
    ('Rental deposit scam: landlord "out of the country"', 'rent-deals-toronto.xyz', 1, 'website', 1900, 6, 9, 0, 'sofia.r',
     'Beautiful 2BR near campus for $950/month. "Landlord" said he is out of the country for work so he can\'t show the unit, '
     'but would send keys by courier once I send first and last month as a deposit. I sent $1,900 by e-transfer. No keys, no reply.',
     [('them', 'The unit is still available! I am currently out of the country for work so I can\'t show it.'),
      ('them', 'Send first and last month ($1,900) by e-transfer and I will courier the keys to you.'),
      ('me', 'Can my friend view it first?'), ('them', 'Sorry, no viewings. Many people are interested, act now.')]),
    ('Kijiji landlord "Daniel Whitmore" wants deposit before viewing', 'Daniel Whitmore', 1, 'social', 0, 14, 4, 0, 'priya_s',
     'Posted a basement apartment on Kijiji. Refused to do a viewing, asked for a $500 holding deposit by e-transfer '
     'to "reserve" it. Photos were taken from an old Airbnb listing (reverse image search).', None),
    ('"CRA" text: your refund is waiting, click to claim', 'cra-refund-canada.top', 2, 'text', 0, 1, 2, 0, 'liam_w',
     'CRA NOTICE: You have an outstanding refund of $486.20. Claim within 24 hours at the link. Link goes to a fake '
     'Government of Canada page that asks for SIN, banking info and card number.',
     [('them', 'CRA NOTICE: You have a pending refund of $486.20. Claim within 24 hours: cra-refund-canada.top/claim')]),
    ('CRA arrest threat call, demanded Google Play gift cards', '(876) 555-0199', 2, 'call', 1500, 4, 8, 0, 'ahmed.h',
     'Caller said he was a CRA officer, my SIN was suspended, and a warrant would be issued for my arrest unless I paid '
     'immediately with Google Play gift cards. Told me not to tell anyone. My uncle lost $1,500 before we realized.', None),
    ('"IRCC officer" says my study permit has errors, pay fine', '(647) 555-0161', 2, 'call', 0, 11, 5, 0, 'sofia.r',
     'Caller knew my name and school. Said there were errors on my immigration file and I would be deported unless I paid '
     'a $2,000 penalty in bitcoin. IRCC does not do this. Hung up.', None),
    ('PayPal phishing email: "your account is limited"', 'paypa1-secure.com', 3, 'email', 0, 2, 7, 0, 'chloe.b',
     'Dear customer, your account has been limited. Verify your identity within 48 hours to avoid suspension. '
     'The link goes to paypa1-secure.com (number 1 instead of letter L). Login page looks exactly like PayPal.', None),
    ('"CRA refund department" emailing from Gmail', 'cra.refund.dept@gmail.com', 2, 'email', 0, 5, 5, 0, 'noah_p',
     'Email from cra.refund.dept@gmail.com says I am eligible for a GST rebate, asks me to reply with my SIN and banking '
     'info. The CRA does not use Gmail.', None),
    ('RBC security alert text links to fake login', 'http://rbc-secure-login.top/verify', 5, 'text', 650, 8, 6, 0, 'emma.l',
     'Text said my RBC account was locked and to verify at the link. Entered my card number and the one-time code they sent. '
     '$650 was e-transferred out within minutes. Bank reimbursed part of it.',
     [('them', 'RBC ALERT: Your account has been locked due to suspicious activity. Verify now: http://rbc-secure-login.top/verify')]),
    ('Interac "deposit pending" link asks for bank login', 'interac-etransfer-deposit.click', 5, 'email', 0, 12, 3, 0, 'daniel_o',
     'Email said I had a $350 e-transfer waiting and to click to deposit. Page asked me to pick my bank and log in. '
     'Real Interac deposits never go through a site like this.', None),
    ('Fake sneaker store, paid $240, nothing arrived', 'maple-deals-outlet.shop', 4, 'website', 240, 19, 4, 0, 'liam_w',
     'Instagram ad for 70% off Jordans. Paid $240 by credit card. Tracking number never worked, emails bounce. '
     'Disputing with my card company.', None),
    ('Canada Post redelivery fee text', 'canadapost-redelivery.info', 8, 'text', 3, 7, 5, 0, 'chloe.b',
     'Text: "Your package could not be delivered due to an incomplete address. Pay $2.99 redelivery fee." Site asks for '
     'full card details. Small fee is bait to steal the card.', None),
    ('"Microsoft support" pop-up with phone number', '1-844-555-0177', 7, 'website', 0, 21, 3, 0, 'jordan.t',
     'Browser pop-up froze the screen and said my computer was infected, call Microsoft at this number. The guy wanted '
     'remote access through AnyDesk and $299 for a "security package". Closed the browser.', None),
    ('Crypto "mentor" on Instagram, could not withdraw', 'CryptoMentor Alex', 6, 'social', 3200, 27, 7, 1, 'daniel_o',
     'Met on Instagram. Showed screenshots of huge profits, guaranteed returns. Got me to deposit $3,200 on a trading site. '
     'Balance showed $9,000 but when I tried to withdraw they demanded a 20% "release fee". Never got anything back.', None),
    ('"Grandson in jail" call to my grandmother', '(416) 555-0123', 9, 'call', 0, 16, 4, 0, 'priya_s',
     'Caller pretended to be my cousin, said he was arrested after a car accident and needed $5,000 bail, and not to tell '
     'his parents. Then a "lawyer" got on the phone. Luckily my grandmother called my aunt first.', None),
    ('Landlord asked for deposit, but the unit was real', '(647) 555-0188', 1, 'text', 0, 10, 1, 5, 'noah_p',
     'Thought this was a scam because he asked for a deposit by e-transfer. Turns out other users viewed the unit and '
     'signed a real lease with him. Leaving this up so others can see the votes.', None),
    ('"Amazon order" call about an iPhone purchase', '(905) 555-0134', 3, 'call', 0, 0, 0, 0, 'demo',
     'Automated call said an iPhone 16 was ordered on my Amazon account for $1,499 and to press 1 to cancel. A person then '
     'asked me to install an app so they could "fix" my account. I hung up.', None),
]

COMMENTS = [
    (0, 'liam_w', 'Got the exact same text yesterday. They said $42/hr for me.', True),
    (0, 'emma.l', 'Reported to the Anti-Fraud Centre as well. Thanks for posting the screenshot.', False),
    (0, 'haya', 'Notice the Telegram interview + pay for a "kit". Textbook job scam.', False),
    (2, 'jordan.t', 'Same photos are on a listing in Montreal. Definitely fake.', False),
    (2, 'maya_k', 'They sent me the same "out of the country" message word for word.', True),
    (5, 'rabiya', 'The 876 area code is Jamaica, not Canada. Never call these back.', False),
    (7, 'nancy', 'Look closely: paypa1 with a one. Great catch.', False),
    (9, 'rishi', 'Call your bank right away if you entered a code, they can sometimes freeze the transfer.', False),
    (16, 'priya_s', 'I viewed this unit in person and it is legit. The landlord was very professional.', False),
]


def make_evidence(contact, lines, name='evidence.png'):
    from PIL import Image, ImageDraw, ImageFont

    def font(size, bold=False):
        names = (['DejaVuSans-Bold.ttf', 'arialbd.ttf', 'Arial Bold.ttf'] if bold else
                 ['DejaVuSans.ttf', 'arial.ttf', 'Arial.ttf', 'Helvetica.ttc'])
        for n in names:
            for prefix in ('', '/usr/share/fonts/truetype/dejavu/', 'C:/Windows/Fonts/', '/Library/Fonts/', '/System/Library/Fonts/'):
                try:
                    return ImageFont.truetype(prefix + n, size)
                except OSError:
                    continue
        try:
            return ImageFont.load_default(size=size)
        except TypeError:
            return ImageFont.load_default()

    W, H = 600, 900
    img = Image.new('RGB', (W, H), '#F4F6F9')
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 110], fill='#FFFFFF')
    d.line([0, 110, W, 110], fill='#E3EAF2', width=2)
    d.ellipse([24, 30, 74, 80], fill='#C9D3DE')
    d.text((49, 55), contact[:1].upper(), fill='#fff', font=font(24, True), anchor='mm')
    d.text((92, 38), contact, fill='#0B1F33', font=font(24, True))
    d.text((92, 70), 'Text Message · Today', fill='#5B6B7C', font=font(16))
    y, f = 140, font(21)
    for who, msg in lines:
        wrapped = textwrap.wrap(msg, 30)
        h = 18 + 30 * len(wrapped)
        w = max(d.textlength(l, font=f) for l in wrapped) + 36
        x = 24 if who == 'them' else W - 24 - w
        d.rounded_rectangle([x, y, x + w, y + h], radius=22, fill='#E9ECF1' if who == 'them' else '#2F6FDE')
        for i, line in enumerate(wrapped):
            d.text((x + 18, y + 10 + 30 * i), line, fill='#0B1F33' if who == 'them' else '#fff', font=f)
        y += h + 18
    d.text((W // 2, H - 30), 'ScamShield demo evidence', fill='#9AA8B6', font=font(14), anchor='mm')
    buf = io.BytesIO()
    img.save(buf, 'PNG')
    return ContentFile(buf.getvalue(), name=name)


class Command(BaseCommand):
    help = 'Load realistic demo data (scam types, users, reports, votes, comments, evidence images).'

    def add_arguments(self, parser):
        parser.add_argument('--reset', action='store_true', help='Delete existing reports, logs and non-staff users first')

    def handle(self, *args, **opts):
        rng = random.Random(11)  # Group 11 :)
        if opts['reset']:
            Report.objects.all().delete()
            SearchLog.objects.all().delete()
            User.objects.filter(is_superuser=False).delete()
            ScamType.objects.all().delete()

        types = []
        for name, icon, desc, tips in TYPES:
            st, _ = ScamType.objects.update_or_create(name=name, defaults={'icon': icon, 'description': desc, 'how_to_spot': tips})
            types.append(st)

        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser('admin', 'admin@scamshield.local', PASSWORD)
        users = {}
        for username, city, bio in USERS:
            u, created = User.objects.get_or_create(username=username, defaults={'email': f'{username.replace(".", "")}@example.com'})
            if created:
                u.set_password(PASSWORD)
                u.save()
            Profile.objects.filter(user=u).update(city=city, bio=bio)
            users[username] = u
        voters = [u for k, u in users.items() if k != 'demo']

        if Report.objects.exists() and not opts['reset']:
            self.stdout.write(self.style.WARNING('Reports already exist; use --reset to reload. Users and types updated.'))
            return

        now = timezone.now()
        created = []
        for (title, ident, ti, channel, amount, days, n_scam, n_safe, author, desc, ev) in REPORTS:
            r = Report.objects.create(
                title=title, identifier=ident, scam_type=types[ti], channel=channel, amount_lost=amount,
                author=users[author], description=desc, view_count=rng.randint(15, 260),
                created_at=now - timedelta(days=days, hours=rng.randint(0, 20), minutes=rng.randint(0, 59)))
            pool = [u for u in voters if u != r.author]
            rng.shuffle(pool)
            for u in pool[:n_scam]:
                Vote.objects.create(report=r, user=u, is_scam=True)
            for u in pool[n_scam:n_scam + n_safe]:
                Vote.objects.create(report=r, user=u, is_scam=False)
            r.recompute_status()
            if ev:
                contact = ident if r.identifier_type == 'phone' else 'Unknown sender'
                Evidence.objects.create(report=r, image=make_evidence(contact, ev, f'report{r.pk}.png'),
                                        caption='Screenshot of the conversation')
            created.append(r)

        for idx, uname, body, targeted in COMMENTS:
            Comment.objects.create(report=created[idx], author=users[uname], body=body, also_targeted=targeted)

        # some lookup history so "trending" and counters have data
        for r, n in [(created[0], 23), (created[2], 14), (created[5], 11), (created[7], 9), (created[4], 6), (created[9], 5)]:
            for _ in range(n):
                SearchLog.objects.create(query=r.identifier, normalized=r.normalized_identifier, kind=r.identifier_type, result_count=1)

        for u in users.values():
            u.profile.recalculate()
        Profile.objects.filter(user__username='admin').update(reputation=0)

        self.stdout.write(self.style.SUCCESS(
            f'Seeded {len(types)} scam types, {len(users)} users, {len(created)} reports, '
            f'{Vote.objects.count()} votes, {Evidence.objects.count()} evidence images.\n'
            f'Log in as demo / {PASSWORD} (member) or admin / {PASSWORD} (moderator).'))
