# coding=utf-8
import sqlite3
from typing import Iterable

from modules.packet import ResourceRecord, Question, Type


class DnsDb:
    __instance = None

    def __new__(cls, *args, **kwargs):
        if cls.__instance is None:
            cls.__instance = object.__new__(cls)
            cls.__instance.__initialized = False
        return cls.__instance

    _TABLE_NAME = 'DnsCache'
    _NAME = 'name'
    _TYPE = 'type'
    _DATA = 'data'
    _IP = 'ip'

    def __init__(self):
        if self.__initialized:
            return
        self.__initialized = True
        self.connection = sqlite3.connect('cache.sqlite')
        self._cursor = self.connection.cursor()
        self._create_table()

    def __del__(self):
        self.connection.commit()
        self.connection.close()

    def _delete_expired_now(self):
        self._cursor.execute(
            f'DELETE FROM {self._TABLE_NAME} WHERE {self._EXPIRY} <= datetime("now", "localtime");'
        )
        self.connection.commit()

    def _create_table(self) -> None:
        self._cursor.execute(
            f'''
            CREATE TABLE IF NOT EXISTS {self._TABLE_NAME} 
            (                
                {self._NAME} varchar(255) NOT NULL,
                {self._TYPE} integer(1) NOT NULL,
                {self._DATA} blob NOT NULL,
                CONSTRAINT record UNIQUE 
                ({self._NAME}, {self._TYPE}, {self._DATA}) ON CONFLICT REPLACE
            );            
            '''
        )
        self._cursor.execute(
            f'''
            DELETE FROM {self._TABLE_NAME};
            '''
        )
        self.connection.commit()

    def select(self, name: str, type: Type) -> Iterable[ResourceRecord]:
        self._cursor.execute(
            f'''SELECT {self._DATA} 
                FROM {self._TABLE_NAME} WHERE 
                {self._NAME} = ? and
                {self._TYPE} = ?
            ''',
            (name, type.value)
        )
        result = self._cursor.fetchall()
        return (ResourceRecord.from_bytes(row[0])[0] for row in result)

    def select_question(self, question: Question) -> Iterable[ResourceRecord]:
        return self.select(question.name, question.type)

    def select_all(self) -> Iterable[ResourceRecord]:
        self._cursor.execute(f'SELECT {self._DATA} FROM {self._TABLE_NAME}')
        result = self._cursor.fetchall()
        return (ResourceRecord.from_bytes(row[0])[0] for row in result)

    def insert(self, record: ResourceRecord, *, commit: bool = True) -> None:
        return self.insert_many((record,), commit=commit)

    def insert_many(self, records: Iterable[ResourceRecord], *, commit: bool = True) -> None:
        rows = []
        count = 0
        for record in records:
            count += 1
            serialized = record.to_bytes()
            rows.extend([record.name, record.type.value, serialized])
        self._cursor.execute(
            f'INSERT INTO {self._TABLE_NAME} ' +
            f'({self._NAME}, {self._TYPE}, {self._DATA}) VALUES ' +
            '(?, ?, ?),' * (count - 1) +
            '(?, ?, ?);',
            rows
        )
        if commit:
            self.connection.commit()
