#
#
#

from collections import defaultdict
from logging import getLogger
from time import sleep

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

__version__ = '0.0.1'


class PorkbunError(ProviderException):
    def __init__(self, data):
        message = None
        try:
            if data['status'] == 'ERROR':
                message = data['message']
        except (IndexError, KeyError, TypeError):
            pass
        super().__init__(message or 'Porkbun error')


class PorkbunAuthenticationError(PorkbunError):
    def __init__(self, data):
        PorkbunError.__init__(self, data)


class PorkbunRateLimitError(PorkbunError):
    def __init__(self, data):
        PorkbunError.__init__(self, data)


class PorkbunClient(object):
    BASE = 'https://api.porkbun.com/api/json/v3'

    SUPPORTS = set(
        (
            'A',
            'MX',
            'CNAME',
            'ALIAS',
            'TXT',
            'NS',
            'AAAA',
            'SRV',
            # 'TLSA',
            'CAA',
            # 'HTTPS',
            # 'SVCB',
        )
    )

    def __init__(
        self,
        api_key,
        secret_api_key,
        timeout=10,
        retry_count=4,
        retry_period=300,
        headers={},
    ):
        self.log = getLogger(f'PorkbunClient[{api_key}]')
        sess = Session()
        sess.headers.update(
            {
                'User-Agent': f'octodns/{octodns_version} octodns-porkbun/{__version__}',
                **headers,
            }
        )
        self._sess = sess
        self._api_key = api_key
        self._secret_api_key = secret_api_key
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_period = retry_period

    def _try_request(self, *args, **kwargs):
        tries = self.retry_count
        while True:  # We'll raise to break after our tries expire
            try:
                return self._request(*args, **kwargs)
            except PorkbunRateLimitError:
                if tries <= 1:
                    raise
                tries -= 1
                self.log.warning(
                    'rate limit encountered, pausing '
                    'for %ds and trying again, %d remaining',
                    self.retry_period,
                    tries,
                )
                sleep(self.retry_period)

    def _request(self, path, data=None):
        # The Porkbun API uses JSON content sent to URI endpoints via HTTP POST
        # https://porkbun.com/api/json/v3/documentation#Overview
        method = 'POST'
        url = f'{self.BASE}{path}'
        self.log.debug('_request: method=%s, url=%s', method, url)
        # https://porkbun.com/api/json/v3/documentation#Authentication
        resp = self._sess.request(
            method,
            url,
            json={
                'apikey': self._api_key,
                'secretapikey': self._secret_api_key,
                **(data or {}),
            },
            timeout=self.timeout,
        )
        self.log.debug('_request:   status=%d', resp.status_code)
        # https://porkbun.com/api/json/v3/documentation#Errors
        if resp.status_code == 400:
            self.log.debug('_request:   data=%s', data)
            raise PorkbunError(resp.json())
        if resp.status_code == 403:
            raise PorkbunAuthenticationError(resp.json())
        if resp.status_code == 429:
            raise PorkbunRateLimitError(resp.json())
        resp.raise_for_status()
        resp_data = resp.json()
        if self._is_error(resp_data):
            raise PorkbunError(resp_data)
        return resp_data

    def _is_error(self, resp):
        return resp['status'] == 'ERROR'

    def _is_success(self, resp):
        return resp['status'] == 'SUCCESS'

    def list_domains(self):
        domains = []
        start = 0
        while True:
            # https://porkbun.com/api/json/v3/documentation#Domain%20List%20All
            resp = self._try_request('/domain/listAll', {'start': start})
            if not resp['domains']:
                break
            domains += resp['domains']
            start += 1000
        return domains

    def get_ns(self, domain):
        domain = domain.rstrip('.')
        resp = self._try_request(f'/domain/getNs/{domain}')
        return resp['ns']

    def update_ns(self, domain, ns):
        domain = domain.rstrip('.')
        resp = self._try_request(f'/domain/updateNs/{domain}', {'ns': ns})
        return self._is_success(resp)

    def list_records(self, domain, type=None, subdomain=None):
        domain = domain.rstrip('.')
        if type:
            path = f'/dns/retrieveByNameType/{domain}/{type}'
            if subdomain:
                subdomain = subdomain.rstrip('.')
                path += f'/{subdomain}'
        else:
            path = f'/dns/retrieve/{domain}'
        resp = self._try_request(path)
        return resp['records']

    def create_record(
        self, domain, type, content, name=None, ttl=None, priority=None
    ):
        domain = domain.rstrip('.')
        data = {'type': type, 'content': content}
        if name is not None:
            data['name'] = name.rstrip('.')
        if ttl is not None:
            data['ttl'] = f'{ttl}'
        if priority is not None:
            data['prio'] = f'{priority}'
        resp = self._try_request(f'/dns/create/{domain}', data)
        return resp['id']

    def get_record(self, domain, id):
        domain = domain.rstrip('.')
        resp = self._try_request(f'/dns/retrieve/{domain}/{id}')
        return resp['records'][0]

    def update_record(
        self, domain, id, type, content, name=None, ttl=None, priority=None
    ):
        domain = domain.rstrip('.')
        data = {'type': type, 'content': content}
        if name is not None:
            data['name'] = name.rstrip('.')
        if ttl is not None:
            data['ttl'] = f'{ttl}'
        if priority is not None:
            data['prio'] = f'{priority}'
        resp = self._try_request(f'/dns/edit/{domain}/{id}', data)
        return self._is_success(resp)

    def delete_record(self, domain, id):
        domain = domain.rstrip('.')
        resp = self._try_request(f'/dns/delete/{domain}/{id}')
        return self._is_success(resp)


class PorkbunProvider(BaseProvider):
    SUPPORTS_GEO = False  # TODO
    SUPPORTS_DYNAMIC = False  # TODO
    SUPPORTS_POOL_VALUE_STATUS = False  # TODO
    SUPPORTS_DYNAMIC_SUBNETS = False  # TODO
    SUPPORTS_MULTIVALUE_PTR = False  # TODO
    SUPPORTS = set(PorkbunClient.SUPPORTS)

    def __init__(
        self,
        id,
        api_key=None,
        secret_api_key=None,
        retry_count=4,
        retry_period=300,
        *args,
        **kwargs,
    ):
        self.log = getLogger(f'PorkbunProvider[{id}]')
        super().__init__(id, *args, **kwargs)
        client = PorkbunClient(
            api_key=api_key,
            secret_api_key=secret_api_key,
            retry_count=retry_count,
            retry_period=retry_period,
        )
        self._client = client
        self._zones = None
        self._zone_records = {}

    def list_zones(self):
        self.log.debug('list_zones:')
        zones = [
            f'{d["domain"]}.'
            for d in self._client.list_domains()
            if not d['notLocal']
        ]
        return sorted(zones)

    def _data_for_multiple(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': [r['content'] for r in records],
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple

    def _data_for_CAA(self, _type, records):
        values = []
        for record in records:
            flags, tag, value = record['content'].split(' ')
            values.append(
                {'flags': flags, 'tag': tag, 'value': value.strip('"')}
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_CNAME(self, _type, records):
        record = records[0]
        return {
            'ttl': record['ttl'],
            'type': _type,
            'value': f'{record["content"]}.',
        }

    _data_for_ALIAS = _data_for_CNAME

    def _data_for_MX(self, _type, records):
        values = []
        for record in records:
            values.append(
                {
                    'preference': record['prio'],
                    'exchange': f'{record["content"]}.',
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_NS(self, _type, records):
        values = []
        for record in records:
            values.append(f'{record["content"]}.')
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_SRV(self, _type, records):
        values = []

        for record in records:
            weight, port, target = record['content'].split(' ')
            values.append(
                {
                    'port': port,
                    'priority': record['prio'],
                    'target': target,
                    'weight': weight,
                }
            )
        return {'type': _type, 'ttl': records[0]['ttl'], 'values': values}

    def _data_for_TXT(self, _type, records):
        values = [value['data'].replace(';', '\\;') for value in records]
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_TLSA(self, _type, records):
        raise NotImplementedError()

    def _data_for_HTTPS(self, _type, records):
        raise NotImplementedError()

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))
        for record in self.zone_records(zone):
            _type = record['type']
            if _type not in self.SUPPORTS:
                self.log.warning(
                    'populate: skipping unsupported %s record', _type
                )
                continue
            values[record['name']][record['type']].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                record = self._record_for(
                    zone, name, _type, records, lenient=lenient
                )
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _params_for_single(self, record):
        yield {
            'content': record.value,
            'name': record.name,
            'ttl': record.ttl,
            'type': record._type,
        }

    def _params_for_multiple(self, record):
        for value in record.values:
            yield {
                'content': value,
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
            }

    _params_for_A = _params_for_multiple

    _params_for_AAAA = _params_for_multiple

    _params_for_NS = _params_for_multiple

    _params_for_CNAME = _params_for_single

    _params_for_ALIAS = _params_for_CNAME

    def _params_for_CAA(self, record):
        for value in record.values:
            yield {
                'content': f'{value.flags} {value.tag} "{value.value}"',
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_MX(self, record):
        for value in record.values:
            yield {
                'content': value.exchange,
                'name': record.name,
                'prio': value.preference,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_TXT(self, record):
        for value in record.values:
            yield {
                'content': value.replace('\\;', ';'),
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_SRV(self, record):
        for value in record.values:
            yield {
                'content': f'{value.weight} {value.port} {value.target}',
                'name': record.name,
                'prio': value.priority,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_TLSA(self, record):
        raise NotImplementedError()

    def _params_for_HTTPS(self, record):
        # for value in record.values:
        #     yield {
        #         'content': f'{value.priority} {value.target} alpn="{value.alpn}" ipv4hint="{value.ipv4hint}" ipv6hint="{value.ipv6hint}"',
        #         'name': record.name,
        #         'ttl': record.ttl,
        #         'type': record._type,
        #     }
        raise NotImplementedError()

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            if zone.name not in self.zones:
                return []

            # populate DNS records, ensure only supported types are considered
            records = [
                record
                for record in self._client.list_records(zone.name)
                if record['type'] in self.SUPPORTS
            ]

            self._zone_records[zone.name] = records

        return self._zone_records[zone.name]

    def _record_for(self, zone, name, _type, records, lenient):
        data_for = getattr(self, f'_data_for_{_type}')
        data = data_for(_type, records)
        record = Record.new(zone, name, data, source=self, lenient=lenient)
        return record

    def _apply_Create(self, change):
        new = change.new
        params_for = getattr(self, f'_params_for_{new._type}')
        for params in params_for(new):
            self._client.create_record(new.zone.name[:-1], **params)

    def _apply_Update(self, change):
        self._apply_Delete(change)
        self._apply_Create(change)

    def _apply_Delete(self, change):
        existing = change.existing
        zone = existing.zone
        for record in self.zone_records(zone):
            if (
                existing.name == record['name']
                and existing._type == record['type']
            ):
                self._client.delete_record(zone.name[:-1], record['id'])

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )
        domain_name = desired.name[:-1]

        self._client.get_ns(domain_name)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change)

        # Clear out the cache if any
        self._zone_records.pop(desired.name, None)
