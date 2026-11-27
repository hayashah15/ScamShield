from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from . import detection, services
from .models import Comment, Evidence, Report, ScamType, Vote

TINY_PNG = (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
            b'\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82')


class DetectionTests(TestCase):
    def test_detect_type(self):
        self.assertEqual(detection.detect_type('(437) 555-0142'), 'phone')
        self.assertEqual(detection.detect_type('+1 437 555 0142'), 'phone')
        self.assertEqual(detection.detect_type('paypa1-secure.com'), 'url')
        self.assertEqual(detection.detect_type('https://x.y.ca/path'), 'url')
        self.assertEqual(detection.detect_type('a.b@gmail.com'), 'email')
        self.assertEqual(detection.detect_type('Daniel Whitmore'), 'name')

    def test_normalize_phone_variants_match(self):
        forms = ['(437) 555-0142', '437.555.0142', '+1-437-555-0142', '14375550142']
        self.assertEqual({detection.normalize(f) for f in forms}, {'4375550142'})

    def test_normalize_url(self):
        self.assertEqual(detection.normalize('https://www.Rent-Deals.xyz/listing?id=3'), 'rent-deals.xyz')

    def test_lookalike_domains(self):
        self.assertIsNotNone(detection.brand_impersonation('paypa1-secure.com'))
        self.assertIsNotNone(detection.brand_impersonation('rbc-secure-login.top'))
        self.assertIsNotNone(detection.brand_impersonation('amaz0n-billing.com'))
        self.assertIsNone(detection.brand_impersonation('paypal.com'))
        self.assertIsNone(detection.brand_impersonation('www.canada.ca'))
        self.assertIsNone(detection.brand_impersonation('wikipedia.org'))

    def test_one_ring_area_code(self):
        labels = [s.label for s in detection.inspect_identifier('876-555-0199')]
        self.assertTrue(any('one-ring' in l for l in labels))

    def test_free_email_impersonation(self):
        sig = detection.inspect_identifier('cra.refund.dept@gmail.com')
        self.assertEqual(sig[0].level, 'danger')

    def test_message_analyzer(self):
        a = detection.analyze_message('CRA: pay immediately with gift cards or a warrant will be issued. Call 876-555-0199')
        self.assertGreaterEqual(a.score, 70)
        self.assertIn('Unusual payment', a.categories)
        self.assertIn('Threats', a.categories)
        self.assertEqual(a.identifiers[0][2], '8765550199')

    def test_benign_message_scores_low(self):
        a = detection.analyze_message('Hey, are we still meeting at the library at 3? Bring the slides.')
        self.assertLess(a.score, 15)


class BaseData(TestCase):
    def setUp(self):
        self.type = ScamType.objects.create(name='Job scam', icon='💼')
        self.author = User.objects.create_user('author', password='pw-12345!')
        self.voters = [User.objects.create_user(f'v{i}', password='pw-12345!') for i in range(5)]
        self.report = Report.objects.create(title='Fake job', identifier='(437) 555-0142', scam_type=self.type,
                                            author=self.author, description='They asked for a $200 training kit fee.')


class ModelTests(BaseData):
    def test_identifier_normalized_on_save(self):
        self.assertEqual(self.report.identifier_type, 'phone')
        self.assertEqual(self.report.normalized_identifier, '4375550142')

    def test_profile_created(self):
        self.assertEqual(self.author.profile.reputation, 0)

    def test_status_becomes_confirmed(self):
        for u in self.voters[:3]:
            Vote.objects.create(report=self.report, user=u, is_scam=True)
        self.assertEqual(self.report.recompute_status(), 'confirmed')
        self.author.profile.refresh_from_db()
        self.assertEqual(self.author.profile.reputation, 5 + 15)

    def test_status_becomes_disputed(self):
        for u in self.voters[:3]:
            Vote.objects.create(report=self.report, user=u, is_scam=False)
        self.assertEqual(self.report.recompute_status(), 'disputed')

    def test_moderator_lock(self):
        self.report.status_locked = True
        self.report.save()
        for u in self.voters[:4]:
            Vote.objects.create(report=self.report, user=u, is_scam=True)
        self.assertEqual(self.report.recompute_status(), 'suspected')

    def test_one_vote_per_user(self):
        from django.db import IntegrityError
        Vote.objects.create(report=self.report, user=self.voters[0], is_scam=True)
        with self.assertRaises(IntegrityError):
            Vote.objects.create(report=self.report, user=self.voters[0], is_scam=False)


class SearchTests(BaseData):
    def test_search_matches_any_phone_format(self):
        res = services.lookup('437.555.0142')
        self.assertEqual([r.pk for r in res.exact], [self.report.pk])
        self.assertGreaterEqual(res.score, 45)

    def test_search_page_and_session_history(self):
        resp = self.client.get(reverse('search'), {'q': '+1 437 555 0142'})
        self.assertContains(resp, 'Fake job')
        self.assertEqual(self.client.session['recent_searches'][0]['q'], '+1 437 555 0142')

    def test_filters(self):
        resp = self.client.get(reverse('search'), {'status': 'confirmed'})
        self.assertNotContains(resp, 'Fake job')

    def test_hidden_reports_not_found(self):
        self.report.is_hidden = True
        self.report.save()
        self.assertEqual(services.lookup('4375550142').exact, [])
        self.assertEqual(self.client.get(self.report.get_absolute_url()).status_code, 404)

    def test_api(self):
        data = self.client.get(reverse('api_check'), {'q': '(437) 555-0142'}).json()
        self.assertTrue(data['ready'])
        self.assertEqual(data['reports'][0]['id'], self.report.pk)


class ViewTests(BaseData):
    def test_public_pages(self):
        for name in ['home', 'search', 'analyze', 'dashboard', 'login', 'register']:
            self.assertEqual(self.client.get(reverse(name)).status_code, 200, name)
        self.assertEqual(self.client.get(self.report.get_absolute_url()).status_code, 200)
        self.assertEqual(self.client.get(reverse('scam_type', args=[self.type.slug])).status_code, 200)

    def test_view_count_once_per_session(self):
        self.client.get(self.report.get_absolute_url())
        self.client.get(self.report.get_absolute_url())
        self.report.refresh_from_db()
        self.assertEqual(self.report.view_count, 1)

    def test_visit_cookie(self):
        resp = self.client.get(reverse('home'))
        self.assertEqual(resp.cookies['ss_visits'].value, '1')

    def test_report_requires_login(self):
        resp = self.client.get(reverse('report_create'))
        self.assertRedirects(resp, reverse('login') + '?next=' + reverse('report_create'))

    @override_settings(MEDIA_ROOT='/tmp/scamshield-test-media')
    def test_create_report_with_evidence(self):
        self.client.login(username='v0', password='pw-12345!')
        import io
        from PIL import Image
        buf = io.BytesIO()
        Image.new('RGB', (20, 20), 'red').save(buf, 'PNG')
        img = SimpleUploadedFile('shot.png', buf.getvalue(), content_type='image/png')
        resp = self.client.post(reverse('report_create'), {
            'identifier': 'rent-deals.xyz', 'identifier_type': '', 'title': 'Rental scam',
            'scam_type': self.type.pk, 'channel': 'website', 'description': 'Asked for deposit before viewing the unit.',
            'amount_lost': '0', 'evidence': [img], 'confirm_truthful': 'on'})
        r = Report.objects.get(title='Rental scam')
        self.assertRedirects(resp, r.get_absolute_url())
        self.assertEqual(r.identifier_type, 'url')
        self.assertEqual(Evidence.objects.filter(report=r).count(), 1)

    def test_report_validation(self):
        self.client.login(username='v0', password='pw-12345!')
        resp = self.client.post(reverse('report_create'), {
            'identifier': '555-12', 'identifier_type': 'phone', 'title': 'x', 'scam_type': self.type.pk,
            'channel': 'text', 'description': 'short', 'amount_lost': '-5'})
        self.assertEqual(resp.status_code, 200)
        form = resp.context['form']
        for f in ['identifier', 'description', 'amount_lost', 'confirm_truthful']:
            self.assertIn(f, form.errors)

    def test_vote_ajax_and_toggle(self):
        self.client.login(username='v1', password='pw-12345!')
        url = reverse('vote', args=[self.report.pk])
        d = self.client.post(url, {'choice': 'scam'}, HTTP_X_REQUESTED_WITH='XMLHttpRequest').json()
        self.assertEqual(d['scam'], 1)
        d = self.client.post(url, {'choice': 'safe'}, HTTP_X_REQUESTED_WITH='XMLHttpRequest').json()
        self.assertEqual((d['scam'], d['safe']), (0, 1))
        d = self.client.post(url, {'choice': 'clear'}, HTTP_X_REQUESTED_WITH='XMLHttpRequest').json()
        self.assertEqual((d['scam'], d['safe']), (0, 0))

    def test_author_cannot_vote(self):
        self.client.login(username='author', password='pw-12345!')
        resp = self.client.post(reverse('vote', args=[self.report.pk]), {'choice': 'scam'},
                                HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertEqual(resp.status_code, 403)

    def test_only_author_can_edit(self):
        self.client.login(username='v2', password='pw-12345!')
        self.assertEqual(self.client.get(reverse('report_edit', args=[self.report.pk])).status_code, 403)
        self.client.login(username='author', password='pw-12345!')
        self.assertEqual(self.client.get(reverse('report_edit', args=[self.report.pk])).status_code, 200)

    def test_comment(self):
        self.client.login(username='v3', password='pw-12345!')
        self.client.post(reverse('add_comment', args=[self.report.pk]), {'body': 'Same here!', 'also_targeted': 'on'})
        self.assertTrue(Comment.objects.filter(report=self.report, also_targeted=True).exists())

    def test_analyze_links_to_reports(self):
        resp = self.client.post(reverse('analyze'), {'message': 'Pay the training kit fee, text 437-555-0142'})
        self.assertContains(resp, 'Linked to reported scam')
