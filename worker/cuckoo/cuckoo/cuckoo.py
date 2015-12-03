
#   Copyright 2014-2015 PUNCH Cyber Analytics Group
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
Overview
========

Interact with a Cuckoo API to submit samples and retrieve results

"""

import time
import argparse

from stoq.scan import get_md5
from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class CuckooWorker(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        worker_opts = parser.add_argument_group('Plugin Options')

        worker_opts.add_argument('-u', '--url',
                                 dest='url_payload',
                                 default=False,
                                 help='Submit URL for Cuckoo Task')

        worker_opts.add_argument('--package',
                                 dest='package',
                                 default=False,
                                 help='analysis package used for analysis')

        worker_opts.add_argument('--timeout',
                                 dest='timeout',
                                 default=False,
                                 help='analysis timeout (in seconds)')

        worker_opts.add_argument('--priority',
                                 dest='priority',
                                 default=False,
                                 help='priority to assign task (1-3)')

        worker_opts.add_argument('--options',
                                 dest='options',
                                 default=False,
                                 help='options to pass to analysis package')

        worker_opts.add_argument('--machine',
                                 dest='machine',
                                 default=False,
                                 help='ID of analysis machine to use')

        worker_opts.add_argument('--platform',
                                 dest='platform',
                                 default=False,
                                 help='platform to select analysis machine')

        worker_opts.add_argument('--tags',
                                 dest='tags',
                                 default=False,
                                 help="""define machine to start by tags.
                                         Platform must be set to use that.
                                         Tags are comma separated""")

        worker_opts.add_argument('--custom',
                                 dest='custom',
                                 default=False,
                                 help="""custom string to pass over for the
                                         analysis and processing/reporting
                                         modules""")

        worker_opts.add_argument('--owner',
                                 dest='owner',
                                 default=False,
                                 help='task owner')

        worker_opts.add_argument('--memory',
                                 dest='memory',
                                 default=False,
                                 help='enable tfull memory dump')

        worker_opts.add_argument('--enforce_timeout',
                                 dest='enforce_timeout',
                                 default=False,
                                 help='enforce execution for full timeout')

        worker_opts.add_argument('--clock',
                                 dest='clock',
                                 default=False,
                                 help="""set virtual machine clock
                                         (format %m-%d-%Y %H:%M:%S)""")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Interact with a Cuckoo API to submit samples and retrieve results

        :param bytes payload: Payload to be submitted to Cuckoo
        :param str url_payload: URL to be submitted to Cuckoo

        :returns: Results returned from Cuckoo
        :rtype: None or dict

        """

        results = None

        if payload:
            submission = self.submit_file(payload, **kwargs)
        elif 'url_payload' in kwargs:
            url_payload = kwargs.pop('url_payload')
            submission = self.submit_url(url_payload, **kwargs)
        else:
            raise Exception('No file or url payload passed')

        task_id = submission['task_ids'][0]

        # Timeout specifications
        interval = 10
        timeout = 300
        current = 0

        while True:
            if current > timeout:
                raise Exception('Timeout')

            time.sleep(interval)
            current += interval
            task = self.view_task(task_id)

            task_status = task['task']['status']

            if task_status == 'reported':
                results = self.view_report(task_id)
                break

        return results

    def list_tasks(self, limit=None, offset=None):
        """
        Returns the list of tasks stored in the internal Cuckoo database

        """
        url = self.url + '/tasks/list'

        if limit:
            url += '/{}'.format(limit)

            if offset:
                url += '/{}'.format(offset)

        response = self.stoq.get_file(url)

        return self.stoq.loads(response)

    def view_task(self, identifier):
        """
        Returns the details on the task assigned to the specified ID

        """
        endpoint = '/tasks/view/{}'.format(identifier)
        url = self.url + endpoint
        response = self.stoq.get_file(url)
        return self.stoq.loads(response)

    def delete_task(self, identifier):
        """
        Removes the given task from the database and deletes the results

        """
        endpoint = '/tasks/delete/{}'.format(identifier)
        url = self.url + endpoint
        response = self.stoq.get_file(url)
        return self.stoq.loads(response)

    def view_report(self, identifier, response_format='json'):
        """
        Returns the report generated out of the analysis of the task
        associated with the specified ID

        """
        endpoint = '/tasks/report/{}/{}'.format(identifier, response_format)
        url = self.url + endpoint
        response = self.stoq.get_file(url)
        return self.stoq.loads(response)

    def get_screenshots(self, identifier, screenshot=''):
        """
        Retrieves one or all screenshots associated with given analysis task ID

        """
        endpoint = '/tasks/screenshots/{}/{}'.format(identifier, screenshot)
        url = self.url + endpoint
        response = self.stoq.get_file(url)
        return response

    def view_md5(self, md5_hash):
        """
        Search the analyzed binaries by MD5 hash

        """
        endpoint = '/files/view/md5/{}'.format(md5_hash)
        url = self.url + endpoint
        response = self.stoq.get_file(url)
        return self.stoq.loads(response)

    def view_sha256(self, sha256_hash):
        """
        Search the analyzed binaries by SHA256 hash

        """
        endpoint = '/files/view/sha256/{}'.format(sha256_hash)
        url = self.url + endpoint
        response = self.stoq.get_file(url)
        return self.stoq.loads(response)

    def view_id(self, identifier):
        """
        Search the analyzed binaries by internal ID

        """
        endpoint = '/files/view/id/{}'.format(identifier)
        url = self.url + endpoint
        response = self.stoq.get_file(url)
        return self.stoq.loads(response)

    def get_file(self, sha256_hash):
        """
        Returns the content of the binary with the specified SHA256

        """
        endpoint = '/files/get/{}'.format(sha256_hash)
        url = self.url + endpoint
        response = self.stoq.get_file(url)
        return response

    def get_pcap(self, identifier):
        """
        Returns the content of the PCAP associated with the given task

        """
        endpoint = '/pcap/get/{}'.format(identifier)
        url = self.url + endpoint
        response = self.stoq.get_file(url)
        return response

    def list_machines(self):
        """
        Returns the list of analysis machines available to Cuckoo

        """
        url = self.url + '/machines/list'
        response = self.stoq.get_file(url)
        return self.stoq.loads(response)

    def view_machine(self, machine_name):
        """
        Returns details on analysis machine associated with the specified name

        """
        endpoint = '/machines/view/{}'.format(machine_name)
        url = self.url + endpoint
        response = self.stoq.get_file(url)
        return self.stoq.loads(response)

    def cuckoo_status(self):
        """
        Returns the basic cuckoo status, including version and tasks overview

        """
        url = self.url + '/cuckoo/status'
        response = self.stoq.get_file(url)
        return self.stoq.loads(response)

    def submit_file(self, payload, **kwargs):
        """
        Adds a file to the list of pending tasks to be processed and analyzed

        """
        params = {}
        url = self.url + '/tasks/create/file'

        valid_args = ('package', 'timeout', 'priority', 'options', 'machine',
                      'platform', 'tags', 'custom', 'owner', 'memory',
                      'enforce_timeout', 'clock')

        for argument_name in kwargs:
            if argument_name in valid_args:
                params[argument_name] = kwargs[argument_name]

        hash_value = get_md5(payload)

        multipart_file = {"file": (hash_value, payload)}
        response = self.stoq.post_file(url, files=multipart_file, data=params)

        return self.stoq.loads(response)

    def submit_url(self, url_payload, **kwargs):
        """
        Adds an URL to the list of pending tasks to be processed and analyzed

        """
        params = {'url': url_payload}
        url = self.url + '/tasks/create/url'

        valid_args = ('package', 'timeout', 'priority', 'options', 'machine',
                      'platform', 'tags', 'custom', 'owner', 'memory',
                      'enforce_timeout', 'clock')

        for argument_name in kwargs:
            if argument_name in valid_args:
                params[argument_name] = kwargs[argument_name]

        response = self.stoq.post_file(url, data=params)

        return self.stoq.loads(response)

