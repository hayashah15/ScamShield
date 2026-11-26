from django import forms
from django.conf import settings

from . import detection
from .models import Comment, Report, ScamType


class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class MultipleImageField(forms.ImageField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('widget', MultipleFileInput(attrs={'accept': 'image/*', 'class': 'file-input'}))
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        single = super().clean
        if isinstance(data, (list, tuple)):
            return [single(d, initial) for d in data if d]
        return [single(data, initial)] if data else []


class ReportForm(forms.ModelForm):
    evidence = MultipleImageField(
        required=False,
        help_text='Screenshots of the message, listing or website (up to 5 images, 5 MB each). '
                  'Blur out your own personal details first.')
    confirm_truthful = forms.BooleanField(
        label='This report is truthful and does not include anyone\'s private information besides the scammer\'s contact.')

    class Meta:
        model = Report
        fields = ['identifier', 'identifier_type', 'title', 'scam_type', 'channel', 'description', 'amount_lost']
        widgets = {
            'identifier': forms.TextInput(attrs={'placeholder': 'e.g. (437) 555-0142, rent-deals.xyz, hr.team@gmail.com',
                                                 'autocomplete': 'off', 'data-live-check': '1'}),
            'title': forms.TextInput(attrs={'placeholder': 'Short summary, e.g. "Fake data-entry job asks for $200 kit"'}),
            'description': forms.Textarea(attrs={'rows': 6, 'placeholder': 'What happened? What did they ask for? '
                                                 'Paste the message if you can.'}),
            'amount_lost': forms.NumberInput(attrs={'min': 0, 'step': '0.01'}),
        }
        labels = {'identifier': 'Phone, website, email or name', 'identifier_type': 'What kind of contact is it?',
                  'channel': 'How did they contact you?', 'amount_lost': 'Money lost (CAD)'}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['identifier_type'].required = False
        self.fields['identifier'].help_text = 'Only the scammer\'s contact. We match any format, e.g. 437-555-0142 = (437) 555 0142.'
        self.fields['identifier_type'].choices = [('', 'Detect automatically')] + list(Report.IdentifierType.choices)
        self.fields['scam_type'].queryset = ScamType.objects.all()
        self.fields['scam_type'].empty_label = 'Choose a scam type…'

    def clean_identifier(self):
        value = self.cleaned_data['identifier'].strip()
        if len(value) < 3:
            raise forms.ValidationError('That is too short to identify anyone.')
        return value

    def clean_title(self):
        title = self.cleaned_data['title'].strip()
        if title.isupper() and len(title) > 10:
            title = title.capitalize()
        return title

    def clean_description(self):
        desc = self.cleaned_data['description'].strip()
        if len(desc) < 20:
            raise forms.ValidationError('Please describe what happened in at least 20 characters.')
        return desc

    def clean_amount_lost(self):
        amount = self.cleaned_data.get('amount_lost') or 0
        if amount < 0:
            raise forms.ValidationError('Amount cannot be negative.')
        return amount

    def clean_evidence(self):
        files = self.cleaned_data.get('evidence') or []
        rules = settings.SCAMSHIELD
        if len(files) > rules['MAX_EVIDENCE_FILES']:
            raise forms.ValidationError(f'You can upload at most {rules["MAX_EVIDENCE_FILES"]} images.')
        for f in files:
            if f.size > rules['MAX_EVIDENCE_MB'] * 1024 * 1024:
                raise forms.ValidationError(f'"{f.name}" is larger than {rules["MAX_EVIDENCE_MB"]} MB.')
        return files

    def clean(self):
        data = super().clean()
        ident, kind = data.get('identifier'), data.get('identifier_type')
        if ident:
            detected = detection.detect_type(ident)
            kind = kind or detected
            data['identifier_type'] = kind
            if kind == 'phone' and len(detection.normalize(ident, 'phone')) != 10:
                self.add_error('identifier', 'Phone numbers must have 10 digits (area code + number).')
            if kind == 'email' and detected != 'email':
                self.add_error('identifier', 'That does not look like a valid email address.')
        return data


class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['body', 'also_targeted']
        widgets = {'body': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Add details, a warning, or how you spotted it…'})}
        labels = {'body': '', 'also_targeted': 'This contacted me too'}

    def clean_body(self):
        body = self.cleaned_data['body'].strip()
        if len(body) < 3:
            raise forms.ValidationError('Comment is too short.')
        return body


class AnalyzeForm(forms.Form):
    message = forms.CharField(
        max_length=5000,
        widget=forms.Textarea(attrs={'rows': 8, 'placeholder': 'Paste a suspicious text, email, DM or job / rental listing here…'}))


class SearchFilterForm(forms.Form):
    SORTS = [('recent', 'Most recent'), ('votes', 'Most confirmed'), ('views', 'Most viewed'), ('loss', 'Highest loss')]
    q = forms.CharField(required=False)
    type = forms.ModelChoiceField(queryset=ScamType.objects.all(), required=False, to_field_name='slug',
                                  empty_label='All scam types')
    status = forms.ChoiceField(required=False, choices=[('', 'Any status')] + list(Report.Status.choices))
    sort = forms.ChoiceField(required=False, choices=SORTS)
