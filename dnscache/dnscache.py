import time
from collections import namedtuple

CacheRecord = namedtuple('Record', ['record', 'addition_time'])


class DnsCache:  # For class IN only
    def __init__(self):
        self.cache = {}

    def is_cached(self, q_entry):
        return q_entry in self.cache

    def get_record(self, question):
        q_entry = question
        return None if not self.is_cached(q_entry) else \
            self.get_actual_records(q_entry)

    def get_actual_records(self, q_entry):
        actual_records = []
        for record in self.cache[q_entry]:
            elapsed_seconds = round(time.time() - record.addition_time)
            record.record.ttl -= elapsed_seconds
            if record.record.ttl > 0:
                actual_records.append(record)
        self.cache[q_entry] = actual_records
        return list(map(lambda r: r.record, actual_records))

    def insert_records(self, question, records):
        if question not in self.cache:
            self.cache[question] = []
        for record in records:
            self.cache[question].append(CacheRecord(record, time.time()))
