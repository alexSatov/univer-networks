import re
from math import floor
from decode import decode

DATE_EXPR = re.compile(r'Date: (.+?)\r\n')
SIZE_EXPR = re.compile(r'RFC822\.SIZE (\d+) ')
TO_EXPR = re.compile(r'To: (.+?\r\n)(\w+:|\)|$)', flags=re.DOTALL)
FROM_EXPR = re.compile(r'From: (.+?\r\n)(\w+:|\)|$)', flags=re.DOTALL)
SUBJECT_EXPR = re.compile(r'Subject: (.+?\r\n)(\w+:|\)|$)', flags=re.DOTALL)
ATTACH_EXPR = re.compile(r'(\d+) \S+ \("attachment" \("filename" (".+?")\)\)')


class LetterInfo:
    def __init__(self, to, from_, subject, date, size, number=0):
        self.to = to
        self.size = size
        self.date = date
        self.from_ = from_
        self.subject = subject
        self.number = number
        self.attachments_count = 0
        self.files = []

    @staticmethod
    def letter_info_from_fetch(fetch, number=0):
        to = re.search(TO_EXPR, fetch)
        from_ = re.search(FROM_EXPR, fetch)
        subject = re.search(SUBJECT_EXPR, fetch)
        date = re.search(DATE_EXPR, fetch)
        size = re.search(SIZE_EXPR, fetch)

        to = decode(to.group(1)).strip() if to else ''
        from_ = decode(from_.group(1)).strip() if from_ else ''
        subject = decode(subject.group(1)).strip() if subject else ''
        date = date.group(1).strip() if date else ''
        size = size.group(1).strip() if size else ''
        return LetterInfo(to, from_, subject, date, size, number)

    def update_with_bodystructure(self, bodystructure):
        info = re.findall(ATTACH_EXPR, bodystructure)
        if info:
            self.attachments_count = len(info)
            for size, filename in info:
                filename = decode(filename)
                size = floor(int(size) / 1024)
                self.files.append('%s (%i KB)' % (filename, size))
