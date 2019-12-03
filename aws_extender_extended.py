# -*- coding: utf-8 -*-
# Version 1.0
from __future__ import absolute_import, print_function
from glob import glob
import re
import time
try:
    import urllib2 as urllib_req
    from urllib2 import HTTPError, URLError, unquote
except ImportError:
    import urllib.request as urllib_req
    from urllib.error import HTTPError, URLError
    from urllib.parse import unquote
import os.path
import xml.etree.cElementTree as CET
from xml.dom.minidom import parse
from array import array
from datetime import datetime
try:
    import boto3
    from botocore.exceptions import ClientError
    from botocore.handlers import disable_signing
    from botocore.compat import XMLParseError
    from botocore.parsers import ResponseParserError
    from boto.s3.connection import S3Connection
    from boto.exception import S3ResponseError
    RUN_TESTS = True
except ImportError:
    RUN_TESTS = False
from burp import IBurpExtender
from burp import IScanIssue
from burp import IScannerCheck
from burp import ITab
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout
from java.awt import GridLayout
from java.net import URL
from org.xml.sax import SAXException

IDENTIFIED_VALUES = set()


class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def __init__(self):
        self.ext_name = 'AWS Extender'
        self.callbacks = None
        self.gui_elements = None
        self.aws_access_key_inpt = None
        self.aws_secret_key_inpt = None
        self.aws_session_token_inpt = None
        self.gs_access_key_inpt = None
        self.gs_secret_key_inpt = None
        self.wordlist_path_inpt = None
        self.checkbox_inpt = None
        self.aws_access_key = ''
        self.aws_secret_key = ''
        self.aws_session_token = ''
        self.gs_access_key = ''
        self.gs_secret_key = ''
        self.wordlist_path = ''

    def registerExtenderCallbacks(self, callbacks):
        """Register extender callbacks."""
        self.callbacks = callbacks

        # Set the name of the extension
        self.callbacks.setExtensionName(self.ext_name)

        # Register the extension as a scanner check
        self.callbacks.registerScannerCheck(self)

        # Build GUI elements
        self.gui_elements = self.build_gui()

        callbacks.customizeUiComponent(self.gui_elements)
        callbacks.addSuiteTab(self)
        self.check_loading_issues()
        self.reload_config()

    def show_errors(self, label):
        """Display error messages."""
        top_label = JLabel(label, JLabel.CENTER)

        frame = JFrame(self.ext_name)
        frame.setSize(550, 300)
        frame.setLayout(GridLayout(1, 1))

        frame.add(top_label)
        frame.setLocationRelativeTo(None)
        frame.setVisible(True)

    def check_loading_issues(self):
        """Check for any loading issues."""
        missing_libs = []
        tips = []
        label = """<html>
              <body style='margin: 10px'>
                <b>The following dependencies could not be loaded successfully:</b><br>
                <ul><li>%s</li></ul><br>
                <b>Tips:</b><br>
                <ul><li>%s</li><br></ul>
                <b>For detailed information on how to load the plugin, see:</b><br>
                <ul>
                  <li>
                    <a href='#'>https://github.com/VirtueSecurity/aws-extender#getting-started</a>
                  </li>
                </ul>
              </body>
            </html>"""

        if not RUN_TESTS:
            missing_libs.append('boto/boto3')
            tips.append('Make sure that the boto/boto3 library is installed properly, and\
                the right path is specified in the "Folder for loading modules" setting.')
        try:
            CET.fromstring('<test></test>')
        except SAXException:
            # Try to workaround "http://bugs.jython.org/issue1127"
            try:
                def xml_parser(**_):
                    class Parser(object):
                        def feed(*_):
                            raise XMLParseError
                        def close(*_):
                            return None
                    return Parser()
                CET.XMLParser = xml_parser
            except TypeError:
                missing_libs.append('SAXParser')
                tips.append("""Run Burp Suite using the following command:
                   <br><code style='background: #f7f7f9; color: red'>$ java -classpath
                   xercesImpl.jar;burpsuite_pro.jar burp.StartBurp</code>""")

        if not missing_libs:
            return
        label %= ('</li><li>'.join(missing_libs), '</li><li>'.join(tips))

        self.show_errors(label)

    def build_gui(self):
        """Construct GUI elements."""
        panel = JPanel(BorderLayout(3, 3))
        panel.setBorder(EmptyBorder(160, 160, 160, 160))

        self.aws_access_key_inpt = JTextField(10)
        self.aws_secret_key_inpt = JTextField(10)
        self.aws_session_token_inpt = JTextField(10)
        self.gs_access_key_inpt = JTextField(10)
        self.gs_secret_key_inpt = JTextField(10)
        self.wordlist_path_inpt = JTextField(10)
        self.checkbox_inpt = JCheckBox('Enabled')

        save_btn = JButton('Save', actionPerformed=self.save_config)

        labels = JPanel(GridLayout(0, 1))
        inputs = JPanel(GridLayout(0, 1))
        panel.add(labels, BorderLayout.WEST)
        panel.add(inputs, BorderLayout.CENTER)

        top_label = JLabel('<html><b>Settings</b><br><br></html>')
        top_label.setHorizontalAlignment(JLabel.CENTER)
        panel.add(top_label, BorderLayout.NORTH)
        labels.add(JLabel('AWS Access Key:'))
        inputs.add(self.aws_access_key_inpt)
        labels.add(JLabel('AWS Secret Key:'))
        inputs.add(self.aws_secret_key_inpt)
        labels.add(JLabel('AWS Session Key (optional):'))
        inputs.add(self.aws_session_token_inpt)
        labels.add(JLabel('GS Access Key:'))
        inputs.add(self.gs_access_key_inpt)
        labels.add(JLabel('GS Secret Key:'))
        inputs.add(self.gs_secret_key_inpt)
        labels.add(JLabel('Wordlist Filepath (optional):'))
        inputs.add(self.wordlist_path_inpt)
        labels.add(JLabel('Passive Mode:'))
        inputs.add(self.checkbox_inpt)
        panel.add(save_btn, BorderLayout.SOUTH)
        return panel

    def save_config(self, _):
        """Save settings."""
        error_message = ''
        wordlist_path = self.wordlist_path_inpt.getText()
        save_setting = self.callbacks.saveExtensionSetting
        save_setting('aws_access_key', self.aws_access_key_inpt.getText())
        save_setting('aws_secret_key', self.aws_secret_key_inpt.getText())
        save_setting('aws_session_token', self.aws_session_token_inpt.getText())
        save_setting('gs_access_key', self.gs_access_key_inpt.getText())
        save_setting('gs_secret_key', self.gs_secret_key_inpt.getText())
        save_setting('wordlist_path', wordlist_path)

        if self.checkbox_inpt.isSelected():
            save_setting('passive_mode', 'True')
        else:
            save_setting('passive_mode', '')

        if wordlist_path and not os.path.isfile(wordlist_path):
            error_message = 'Error: Invalid filepath for the "Wordlist Filepath" setting.'
            self.show_errors(error_message)

        self.reload_config()

    def reload_config(self):
        """Reload saved settings."""
        global RUN_TESTS
        load_setting = self.callbacks.loadExtensionSetting
        aws_access_key_val = load_setting('aws_access_key') or ''
        aws_secret_key_val = load_setting('aws_secret_key') or ''
        aws_session_token_val = load_setting('aws_session_token') or ''
        gs_access_key_val = load_setting('gs_access_key') or ''
        gs_secret_key_val = load_setting('gs_secret_key') or ''
        wordlist_path_val = load_setting('wordlist_path') or ''
        checkbox_inpt_val = load_setting('passive_mode')
        checkbox_inpt_val = bool(str(checkbox_inpt_val)) if checkbox_inpt_val else False
        if checkbox_inpt_val:
            RUN_TESTS = False
        else:
            RUN_TESTS = True

        self.aws_access_key = aws_access_key_val
        self.aws_secret_key = aws_secret_key_val
        self.aws_session_token = aws_session_token_val
        self.gs_access_key = gs_access_key_val
        self.gs_secret_key = gs_secret_key_val
        self.wordlist_path = wordlist_path_val
        self.aws_access_key_inpt.setText(aws_access_key_val)
        self.aws_secret_key_inpt.setText(aws_secret_key_val)
        self.aws_session_token_inpt.setText(aws_session_token_val)
        self.gs_access_key_inpt.setText(gs_access_key_val)
        self.gs_secret_key_inpt.setText(gs_secret_key_val)
        self.wordlist_path_inpt.setText(wordlist_path_val)
        self.checkbox_inpt.setSelected(checkbox_inpt_val)

    def getTabCaption(self):
        """Return tab caption."""
        return self.ext_name

    def getUiComponent(self):
        """Return GUI elements."""
        return self.gui_elements

    def doPassiveScan(self, request_response):
        """Perform a passive scan."""
        scan_issues = []
        opts = {'aws_access_key': self.aws_access_key,
                'aws_secret_key': self.aws_secret_key,
                'aws_session_token': self.aws_session_token,
                'gs_access_key': self.gs_access_key,
                'gs_secret_key': self.gs_secret_key,
                'wordlist_path': self.wordlist_path}
        bucket_scan = BucketScan(request_response, self.callbacks, opts)
        bucket_issues = bucket_scan.check_buckets()
        cognito_scan = CognitoScan(request_response, self.callbacks)
        cognito_issues = cognito_scan.identify_identity_pools()
        s3_secrets = S3SecretsScan(request_response, self.callbacks)
        s3_secrets_issues = s3_secrets.check_res_secrets()

        scan_issues = bucket_issues + cognito_issues + s3_secrets_issues
        if len(scan_issues) > 0:
            return scan_issues
        return None

    def doActiveScan(self, request_response, insertion_point):
        scan_issues = []
        opts = {'aws_access_key': self.aws_access_key,
                'aws_secret_key': self.aws_secret_key}

        s3_secrets = S3SecretsScan(request_response, self.callbacks)
        s3_secrets_issues = s3_secrets.check_metadata_secrets(insertion_point)
        s3_buckets = S3BucketScan(request_response, self.callbacks, opts)
        s3_buckets_issues = s3_buckets.scan_S3_buckets(insertion_point)

        scan_issues = s3_secrets_issues + s3_buckets_issues
        if len(scan_issues) > 0:
            return scan_issues
        return None

    @staticmethod
    def consolidateDuplicateIssues(existing_issue, new_issue):
        """Eliminate duplicate issues."""
        if existing_issue.getIssueDetail() == new_issue.getIssueDetail():
            return -1
        else:
            return 0


class BucketScan(object):
    """Scan cloud storage buckets."""
    def __init__(self, request_response, callbacks, opts):
        self.request_response = request_response
        self.callbacks = callbacks
        self.helpers = self.callbacks.getHelpers()
        bytesToString = self.helpers.bytesToString
        self.request = self.request_response.getRequest()
        self.request_str = bytesToString(self.request)
        self.request_len = len(self.request_str)
        self.request_str = self.request_str.encode('utf-8', 'replace')
        self.response = self.request_response.getResponse()
        self.response_str = bytesToString(self.response)
        self.response_len = len(self.response_str)
        self.response_str = self.response_str.encode('utf-8', 'replace')
        self.offset = array('i', [0, 0])
        self.current_url = self.helpers.analyzeRequest(self.request_response).getUrl()
        self.scan_issues = []
        self.aws_access_key = opts['aws_access_key']
        self.aws_secret_key = opts['aws_secret_key']
        self.aws_session_token = opts['aws_session_token']
        self.gs_access_key = opts['gs_access_key']
        self.gs_secret_key = opts['gs_secret_key']
        self.wordlist_path = opts['wordlist_path']
        try:
            self.boto3_client = boto3.client('s3',
                                             aws_access_key_id=self.aws_access_key,
                                             aws_secret_access_key=self.aws_secret_key,
                                             aws_session_token=self.aws_session_token)
            self.boto_s3_con = S3Connection(
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                host='s3.amazonaws.com'
            )
            self.boto_gs_con = S3Connection(
                aws_access_key_id=self.gs_access_key,
                aws_secret_access_key=self.gs_secret_key,
                host='storage.googleapis.com'
            )

            if not (self.aws_access_key and self.aws_secret_key):
                self.boto3_client.meta.events.register('choose-signer.s3.*', disable_signing)
                self.boto_s3_con = S3Connection(anon=True)

            if not (self.gs_access_key and self.gs_secret_key):
                self.boto_gs_con = S3Connection(anon=True, host='storage.googleapis.com')
        except NameError:
            pass

    def bucket_exists(self, bucket_name, bucket_type):
        """Confirm if an S3 bucket exists."""
        if bucket_type == 'S3':
            try:
                self.boto3_client.head_bucket(Bucket=bucket_name)
            except ClientError as error:
                error_code = int(error.response['Error']['Code'])
                if error_code == 404:
                    return False
        elif bucket_type == 'GS':
            try:
                self.boto_gs_con.head_bucket(bucket_name)
            except S3ResponseError as error:
                if error.error_code == 'NoSuchBucket':
                    return False
        elif bucket_type == 'Azure':
            try:
                bucket_url = 'https://' + bucket_name + '?comp=list&maxresults=10'
                urllib_req.urlopen(urllib_req.Request(bucket_url), timeout=20)
            except (HTTPError, URLError):
                if not self.wordlist_path:
                    return False
        return True

    def test_bucket(self, bucket_name, bucket_type):
        """Test for buckets misconfiguration issues."""
        grants = []
        issues = []
        keys = []

        def enumerate_keys(bucket, bucket_name, bucket_type):
            """Enumerate bucket keys."""
            try:
                with open(self.wordlist_path) as wordlist:
                    wordlist_keys = wordlist.read()
                    key_list = wordlist_keys.split('\n')
            except IOError:
                return

            if bucket_type != 'Azure':
                for key in key_list:
                    try:
                        key = bucket.get_key(key).key
                        self.test_object(bucket_name, bucket_type, key, False)
                    except (S3ResponseError, AttributeError):
                        continue
            else:
                bucket = bucket if bucket.endswith('/') else bucket + '/'
                for key in key_list:
                    try:
                        request = urllib_req.Request(bucket + key)
                        urllib_req.urlopen(request, timeout=20)
                        keys.append(key)
                    except (HTTPError, URLError):
                        continue

        if bucket_type == 'S3':
            bucket = self.boto_s3_con.get_bucket(bucket_name, validate=False)
            try:
                bucket_acl = bucket.get_acl().acl
                for grant in bucket_acl.grants:
                    grants.append((grant.display_name or grant.uri or grant.id or
                                   grant.email_address) + '->' + grant.permission)
                issues.append('s3:GetBucketAcl<ul><li>%s</li></ul>' % '</li><li>'.join(grants))
            except S3ResponseError as error:
                print('Error Code (get_bucket_acl): ' + str(error.error_code))

            try:
                self.boto3_client.get_bucket_cors(Bucket=bucket_name)
                issues.append('s3:GetBucketCORS')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_cors): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetBucketCORS')

            try:
                self.boto3_client.get_bucket_lifecycle(Bucket=bucket_name)
                issues.append('s3:GetLifecycleConfiguration')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_lifecycle): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetLifecycleConfiguration')

            try:
                self.boto3_client.get_bucket_notification(Bucket=bucket_name)
                issues.append('s3:GetBucketNotification')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_notification): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetBucketNotification')

            try:
                self.boto3_client.get_bucket_policy(Bucket=bucket_name)
                issues.append('s3:GetBucketPolicy')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_policy): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetBucketPolicy')

            try:
                self.boto3_client.get_bucket_tagging(Bucket=bucket_name)
                issues.append('s3:GetBucketTagging')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_tagging): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetBucketTagging')

            try:
                self.boto3_client.get_bucket_website(Bucket=bucket_name)
                issues.append('s3:GetBucketWebsite')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (get_bucket_website): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:GetBucketWebsite')

            try:
                self.boto3_client.list_multipart_uploads(Bucket=bucket_name)
                issues.append('s3:ListMultipartUploadParts')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (list_multipart_uploads): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:ListMultipartUploadParts')

            try:
                i = 0
                for k in bucket.list():
                    i = i + 1
                    keys.append(k.key)
                    if i == 10:
                        break
                issues.append('s3:ListBucket<ul><li>%s</li></ul>' % '</li><li>'.join(keys))
            except S3ResponseError as error:
                print('Error Code (list): ' + str(error.error_code))
                if self.wordlist_path:
                    enumerate_keys(bucket, bucket_name, 'S3')

            try:
                self.boto3_client.put_bucket_cors(
                    Bucket=bucket_name,
                    CORSConfiguration={
                        'CORSRules': [
                            {
                                'AllowedMethods': [
                                    'GET'
                                ],
                                'AllowedOrigins': [
                                    '*'
                                ]
                            }
                        ]
                    }
                )
                issues.append('s3:PutBucketCORS')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_cors): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketCORS')

            try:
                self.boto3_client.put_bucket_lifecycle_configuration(
                    Bucket=bucket_name,
                    LifecycleConfiguration={
                        'Rules': [
                            {
                                'Status': 'Disabled',
                                'Prefix': 'test'
                            }
                        ]
                    }
                )
                issues.append('s3:PutLifecycleConfiguration')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_lifecycle_configuration): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutLifecycleConfiguration')

            try:
                self.boto3_client.put_bucket_logging(
                    Bucket=bucket_name,
                    BucketLoggingStatus={}
                )
                issues.append('s3:PutBucketLogging')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_logging): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketLogging')

            try:
                self.boto3_client.put_bucket_notification(
                    Bucket=bucket_name,
                    NotificationConfiguration={
                        'TopicConfiguration': {
                            'Events': ['s3:ReducedRedundancyLostObject'],
                            'Topic': 'arn:aws:sns:us-west-2:444455556666:sns-topic-one'
                        }
                    }
                )
                issues.append('s3:PutBucketNotification')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_notification): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketNotification')

            try:
                self.boto3_client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={
                        'TagSet': [
                            {
                                'Key': 'test',
                                'Value': 'test'
                            }
                        ]
                    }
                )
                issues.append('s3:PutBucketTagging')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_tagging): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketTagging')

            try:
                self.boto3_client.put_bucket_website(
                    Bucket=bucket_name,
                    WebsiteConfiguration={
                        'ErrorDocument': {
                            'Key': 'test'
                        },
                        'IndexDocument': {
                            'Suffix': 'test'
                        }
                    }
                )
                issues.append('s3:PutBucketWebsite')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_website): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketWebsite')

            try:
                self.boto3_client.put_object(
                    Body=b'test',
                    Bucket=bucket_name,
                    Key='test.txt'
                )
                issues.append('s3:PutObject<ul><li>test.txt</li></ul>')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_object): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutObject')

            if '.' in bucket_name:
                try:
                    self.boto3_client.put_bucket_acl(
                        GrantFullControl='uri="http://acs.amazonaws.com/groups/global/AllUsers"',
                        Bucket=bucket_name
                    )
                    issues.append('s3:PutBucketAcl')
                except ClientError as error:
                    error_code = error.response['Error']['Code']
                    print('Error Code (put_bucket_acl): ' + str(error_code))
                except ResponseParserError:
                    issues.append('s3:PutBucketAcl')
            else:
                try:
                    bucket.add_email_grant('FULL_CONTROL', 0)
                    issues.append('s3:PutBucketAcl')
                except S3ResponseError as error:
                    if error.error_code == 'UnresolvableGrantByEmailAddress':
                        issues.append('s3:PutBucketAcl')

            try:
                self.boto3_client.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy='''
                        {
                            "Version":"2012-10-17",
                            "Statement": [
                                {
                                    "Effect":"Allow",
                                    "Principal": "*",
                                    "Action":["s3:GetBucketPolicy"],
                                    "Resource":["arn:aws:s3:::%s/*"]
                                }
                            ]
                        } ''' % bucket_name
                )
                issues.append('s3:PutBucketPolicy')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_bucket_policy): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutBucketPolicy')
        elif bucket_type == 'GS':
            bucket = self.boto_gs_con.get_bucket(bucket_name, validate=False)

            try:
                i = 0
                for k in bucket.list():
                    i = i + 1
                    keys.append(k.key)
                    if i == 10:
                        break
                issues.append('READ<ul><li>%s</li></ul>' % '</li><li>'.join(keys))
            except S3ResponseError as error:
                print('Error Code (list): ' + str(error.error_code))
                if self.wordlist_path:
                    enumerate_keys(bucket, bucket_name, 'GS')
            try:
                key = bucket.new_key('test.txt')
                key.set_contents_from_string('')
                issues.append('WRITE<ul><li>test.txt</li></ul>')
            except S3ResponseError as error:
                print('Error Code (set_contents_from_string): ' + str(error.error_code))

            try:
                bucket.add_email_grant('FULL_CONTROL', 0)
                issues.append('FULL_CONTROL')
            except S3ResponseError as error:
                if error.error_code == 'UnresolvableGrantByEmailAddress':
                    issues.append('FULL_CONTROL')
                else:
                    print('Error Code (add_email_grant): ' + str(error.error_code))
            except AttributeError as error:
                if error.message.startswith("'Policy'"):
                    issues.append('FULL_CONTROL')
                else:
                    raise
        elif bucket_type == 'Azure':
            bucket_url = 'https://' + bucket_name
            try:
                request = urllib_req.Request(bucket_url + '?comp=list&maxresults=10')
                response = urllib_req.urlopen(request, timeout=20)
                blobs = parse(response).documentElement.getElementsByTagName('Name')
                for blob in blobs:
                    keys.append(blob.firstChild.nodeValue.encode('utf-8'))
                issues.append('Full public read access<ul><li>%s</li></ul>' %
                              '</li><li>'.join(keys))
            except (AttributeError, HTTPError, URLError):
                if self.wordlist_path:
                    enumerate_keys(bucket_url, bucket_name, 'Azure')
                    if keys:
                        issues.append('Public read access for blobs only<ul><li>%s</li></ul>' %
                                      '</li><li>'.join(keys))

        if not issues:
            return False
        if ('s3:PutBucketAcl' in issues or 'FULL_CONTROL' in issues) or len(issues) > 4:
            issue_level = 'High'
        elif len(issues) > 2 or ('READ' in issues and
                                 'WRITE<ul><li>test.txt</li></ul>' in issues):
            issue_level = 'Medium'
        else:
            issue_level = 'Low'

        issue_name = '%s Bucket Misconfiguration' % bucket_type
        issue_detail = '''The "%s" %s bucket grants the following permissions:<br>
                         <li>%s</li><br><br>''' % (bucket_name, bucket_type,
                                                   '</li><li>'.join(issues))

        return {'issue_name': issue_name, 'issue_detail': issue_detail,
                'issue_level': issue_level}

    def check_timestamp(self, bucket_url, bucket_type, timestamp):
        """Check timestamps of signed URLs."""
        timestamp_raw = timestamp
        offsets = []
        mark_request = False
        start = 0

        try:
            if bucket_type != 'Azure':
                now = int(time.time())
                diff = (int(timestamp) - now) / 3600
            else:
                timestamp = unquote(timestamp)
                timestamp = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S%fZ')
                diff = int((timestamp - datetime.now()).total_seconds()) / 3600
        except ValueError:
            return

        if diff > 24:
            start = self.helpers.indexOf(self.response,
                                         timestamp_raw, True, 0, self.response_len)
            if start < 0:
                start = self.helpers.indexOf(self.request,
                                             timestamp_raw, True, 0, self.request_len)
                mark_request = True
            self.offset[0] = start
            self.offset[1] = start + len(timestamp_raw)
            offsets.append(self.offset)
            if mark_request:
                markers = [self.callbacks.applyMarkers(self.request_response, offsets, None)]
            else:
                markers = [self.callbacks.applyMarkers(self.request_response, None, offsets)]
            issue_name = '%s Signed URL Excessive Expiration Time' % bucket_type
            issue_level = 'Information'
            issue_detail = '''The following %s signed URL was found to be valid for more than
                24 hours (expires in %sh):<br><li>%s</li>''' % (bucket_type, diff, bucket_url)
            self.scan_issues.append(
                ScanIssue(self.request_response.getHttpService(),
                          self.current_url, markers, issue_name, issue_level, issue_detail)
            )

    def test_object(self, bucket_name, bucket_type, key, mark=True):
        """Test individual bucket objects."""
        issues = []
        grants = []
        markers = []
        offsets = []
        issue_name = ''
        permission = ''
        mark_request = False
        norm_key = key.replace('\\', '')

        if bucket_type == 'S3':
            bucket = self.boto_s3_con.get_bucket(bucket_name, validate=False)
        else:
            bucket = self.boto_gs_con.get_bucket(bucket_name, validate=False)

        try:
            key_obj = bucket.get_key(norm_key)
        except S3ResponseError:
            return

        if not key_obj:
            return
        issues.append('READ')

        try:
            key_acl = key_obj.get_acl().acl
            for grant in key_acl.grants:
                grants.append((grant.display_name or grant.uri or grant.id or
                               grant.email_address) + '->' + grant.permission)
            permission = 's3:GetObjectAcl' if bucket_type == 'S3' else 'getIamPolicy'
            issues.append('%s<ul><li>%s</li></ul>' % (permission, '</li><li>'.join(grants)))
        except S3ResponseError:
            pass

        if '.' in bucket_name and bucket_type == 'S3':
            try:
                self.boto3_client.put_object_acl(
                    GrantFullControl='uri="http://acs.amazonaws.com/groups/global/AllUsers"',
                    Bucket=bucket_name,
                    Key=norm_key
                )
                issues.append('s3:PutObjectAcl')
            except ClientError as error:
                error_code = error.response['Error']['Code']
                print('Error Code (put_object_acl): ' + str(error_code))
            except ResponseParserError:
                issues.append('s3:PutObjectAcl')
        else:
            try:
                key_obj.add_email_grant('FULL_CONTROL', 0)
                permission = 's3:PutObjectAcl' if bucket_type == 'S3' else 'FULL_CONTROL'
                issues.append(permission)
            except S3ResponseError as error:
                if error.error_code == 'UnresolvableGrantByEmailAddress':
                    permission = 's3:PutObjectAcl' if bucket_type == 'S3' else 'FULL_CONTROL'
                    issues.append(permission)

        if not issues:
            return
        if 'READ' in issues and len(issues) < 2:
            issue_level = 'Information'
            issue_name = '%s Object Publicly Accessible' % bucket_type
        elif 's3:PutObjectAcl' in issues or 'FULL_CONTROL' in issues:
            issue_level = 'High'
        else:
            issue_level = 'Low'

        start = self.helpers.indexOf(self.response,
                                     key, True, 0, self.response_len)

        if start < 0 and mark:
            start = self.helpers.indexOf(self.request,
                                         key, True, 0, self.request_len)
            mark_request = True

        self.offset[0] = start
        self.offset[1] = start + len(key)
        offsets.append(self.offset)

        if mark_request:
            markers = [self.callbacks.applyMarkers(self.request_response, offsets, None)]
        elif mark:
            markers = [self.callbacks.applyMarkers(self.request_response, None, offsets)]

        if not issue_name:
            issue_name = '%s Object Misconfiguration' % bucket_type
        issue_detail = '''The following ACL grants were found set on the "%s" object of
            the "%s" %s bucket:<br><li>%s</li>''' % (norm_key, bucket_name, bucket_type,
                                                     '</li><li>'.join(issues))
        self.scan_issues.append(
            ScanIssue(self.request_response.getHttpService(),
                      self.current_url, markers, issue_name, issue_level, issue_detail)
        )

    def check_buckets(self):
        """Check storage buckets."""
        current_url_str = str(unicode(self.current_url, 'utf-8'))
        host, path = re.findall(r'\w+://([\w.-]+)(?::\d+)?(?:/([^\s?#]*))?', current_url_str)[0]

        # Matches S3 bucket names
        s3_buckets_regex = re.compile(
            r'((?:\w+://)?(?:([\w.-]+)\.s3[\w.-]*\.amazonaws\.com|s3(?:[\w.-]*\.amazonaws\.com(?:(?::\d+)?\\?/)*|://)([\w.-]+))(?:(?::\d+)?\\?/([^\s?#]*))?(?:.*?\?.*Expires=(\d+))?)',
            re.I)
        s3_bucket_matches = re.findall(s3_buckets_regex, current_url_str)
        s3_bucket_matches += re.findall(s3_buckets_regex, self.request_str)
        s3_bucket_matches += re.findall(s3_buckets_regex, self.response_str)

        # Matches GS bucket names
        gs_buckets_regex = re.compile(
            r'((?:\w+://)?(?:([\w.-]+)\.storage[\w-]*\.googleapis\.com|(?:(?:console\.cloud\.google\.com/storage/browser/|storage[\w-]*\.googleapis\.com)(?:(?::\d+)?\\?/)*|gs://)([\w.-]+))(?:(?::\d+)?\\?/([^\s?#]*))?(?:.*\?.*Expires=(\d+))?)',
            re.I)
        gs_bucket_matches = re.findall(gs_buckets_regex, current_url_str)
        gs_bucket_matches += re.findall(gs_buckets_regex, self.request_str)
        gs_bucket_matches += re.findall(gs_buckets_regex, self.response_str)

        # Matches Azure container URIs
        az_buckets_regex = re.compile(
            r'(([\w.-]+\.blob\.core\.windows\.net(?::\d+)?\\?/[\w.-]+)(?:.*?\?.*se=([\w%-]+))?)',
            re.I)
        az_bucket_matches = re.findall(az_buckets_regex, current_url_str)
        az_bucket_matches += re.findall(az_buckets_regex, self.request_str)
        az_bucket_matches += re.findall(az_buckets_regex, self.response_str)

        if RUN_TESTS:
            s3_bucket_matches.append(('', host, '', path))
            gs_bucket_matches.append(('', host, '', path))

        def assess_buckets(bucket_matches, bucket_type):
            """Assess identified buckets."""
            mark_request = False
            for i in xrange(0, len(bucket_matches)):
                issues = []
                offsets = []
                bucket_match = bucket_matches[i]
                bucket_url = bucket_match[0]
                bucket_name = bucket_match[1] or bucket_match[2]
                timestamp = bucket_match[-1]
                bucket_tuple = (bucket_name, host)
                timestamp_tuple = (timestamp, bucket_url, host)
                if RUN_TESTS and not self.bucket_exists(bucket_name, bucket_type):
                    continue
                try:
                    key = bucket_match[3]
                    key_tuple = (key, bucket_name, host)
                    if key and key_tuple not in IDENTIFIED_VALUES and RUN_TESTS:
                        self.test_object(bucket_name, bucket_type, key)
                    IDENTIFIED_VALUES.add(key_tuple)
                except IndexError:
                    pass
                if timestamp and timestamp_tuple not in IDENTIFIED_VALUES:
                    self.check_timestamp(bucket_url, bucket_type, timestamp)
                IDENTIFIED_VALUES.add(timestamp_tuple)
                if bucket_tuple in IDENTIFIED_VALUES:
                    continue
                IDENTIFIED_VALUES.add(bucket_tuple)
                start = self.helpers.indexOf(self.response,
                                             bucket_name, True, 0, self.response_len)
                if start < 0:
                    start = self.helpers.indexOf(self.request,
                                                 bucket_name, True, 0, self.request_len)
                    mark_request = True
                self.offset[0] = start
                self.offset[1] = start + len(bucket_name)
                offsets.append(self.offset)
                if mark_request:
                    markers = [self.callbacks.applyMarkers(self.request_response, offsets, None)]
                else:
                    markers = [self.callbacks.applyMarkers(self.request_response, None, offsets)]
                if RUN_TESTS:
                    issues = self.test_bucket(bucket_name, bucket_type)
                    if issues:
                        self.scan_issues.append(
                            ScanIssue(self.request_response.getHttpService(),
                                      self.helpers.analyzeRequest(self.request_response).getUrl(),
                                      markers, issues['issue_name'], issues['issue_level'], issues['issue_detail']
                                     )
                        )
                if not issues:
                    issue_name = '%s Bucket Detected' % bucket_type
                    issue_level = 'Information'
                    issue_detail = '''The following %s bucket has been identified:<br>
                        <li>%s</li>''' % (bucket_type, bucket_name)
                    self.scan_issues.append(
                        ScanIssue(self.request_response.getHttpService(),
                                  self.current_url, markers, issue_name, issue_level, issue_detail)
                    )
        if s3_bucket_matches:
            assess_buckets(s3_bucket_matches, 'S3')

        if gs_bucket_matches:
            assess_buckets(gs_bucket_matches, 'GS')

        if az_bucket_matches:
            assess_buckets(az_bucket_matches, 'Azure')

        return self.scan_issues


class CognitoScan(object):
    """Identify and test Cognito identity pools."""
    def __init__(self, request_response, callbacks):
        self.request_response = request_response
        self.callbacks = callbacks
        self.helpers = self.callbacks.getHelpers()
        self.current_url = self.helpers.analyzeRequest(self.request_response).getUrl()
        self.scan_issues = []

    def obtain_unauth_token(self, identity_pool_id, identity_id, region, markers):
        """Obtain an unauthenticated identity token."""
        client = boto3.client('cognito-identity', region_name=region)
        try:
            token = client.get_open_id_token(IdentityId=identity_id)['Token']
        except (ClientError, KeyError):
            return
        issue_name = 'Cognito Unauthenticated Identities Enabled'
        issue_level = 'Information'
        issue_detail = '''The following identity pool allows unauthenticated identities:
            <br><ul><li>%s</li></ul><br>The following identity ID has been obtained:
            <ul><li>%s</li></ul><br>The following token has been obtained:
            <ul><li>%s</li></ul>''' % (identity_pool_id, identity_id, token)
        self.scan_issues.append(
            ScanIssue(self.request_response.getHttpService(),
                      self.current_url, markers, issue_name, issue_level, issue_detail)
        )

    def identify_identity_pools(self):
        """Identify Cognito identity pools."""
        bytesToString = self.helpers.bytesToString
        request = self.request_response.getRequest()
        request_str = bytesToString(request)
        request_len = len(request_str)
        request_str = request_str.encode('utf-8', 'replace')
        response = self.request_response.getResponse()
        response_str = bytesToString(response)
        response_len = len(response_str)
        response_str = response_str.encode('utf-8', 'replace')
        identity_pool_regex = re.compile(
            r'((us-[\w-]+):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
            re.I)
        identity_pools = re.findall(identity_pool_regex, request_str)
        identity_pools += re.findall(identity_pool_regex, response_str)

        def verify_identity_pools(identity_pool_ids):
            """Verify identity pools."""
            offset = array('i', [0, 0])
            host = re.search(r'\w+://([\w.-]+)', str(self.current_url)).group(1)
            for i in xrange(0, len(identity_pool_ids)):
                offsets = []
                identity_id = ''
                mark_request = False
                identity_pool_id = identity_pool_ids[i]
                region = identity_pool_id[1]
                identity_pool_id = identity_pool_id[0]
                identity_pool_tuple = (identity_pool_id, host)
                if identity_pool_id and identity_pool_tuple in IDENTIFIED_VALUES:
                    continue
                try:
                    client = boto3.client('cognito-identity', region_name=region)
                    identity_id = client.get_id(IdentityPoolId=identity_pool_id)
                    identity_id = identity_id['IdentityId'].encode('utf-8')
                except NameError:
                    pass
                except ClientError:
                    continue
                start = self.helpers.indexOf(response,
                                             identity_pool_id, True, 0, response_len)
                if start < 0:
                    start = self.helpers.indexOf(request,
                                                 identity_pool_id, True, 0, request_len)
                    mark_request = True
                offset[0] = start
                offset[1] = start + len(identity_pool_id)
                offsets.append(offset)
                if mark_request:
                    markers = [self.callbacks.applyMarkers(self.request_response, offsets, None)]
                else:
                    markers = [self.callbacks.applyMarkers(self.request_response, None, offsets)]
                issue_name = 'Cognito Identity Pool Detected'
                issue_level = 'Information'
                issue_detail = '''The following identity pool ID has been identified:<br>
                    <li>%s</li>''' % identity_pool_id
                self.scan_issues.append(
                    ScanIssue(self.request_response.getHttpService(),
                              self.current_url, markers, issue_name, issue_level, issue_detail)
                )
                IDENTIFIED_VALUES.add(identity_pool_tuple)
                if identity_id and RUN_TESTS:
                    self.obtain_unauth_token(identity_pool_id, identity_id, region, markers)

        if identity_pools:
            verify_identity_pools(identity_pools)

        return self.scan_issues

class S3SecretsScan(object):
    def __init__(self, request_response, callbacks):
        self.request_response = request_response
        self.callbacks = callbacks
        self.helpers = self.callbacks.getHelpers()
        self.secrets = ['S3_KEY', 'S3_SECRET', 'AWS_ACCESS_KEY_ID',
            'AWS_SECRET_ACCESS_KEY', 'AccessKeyId', 'SecretAccessKey',
            'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token'
        ]

    def check_res_secrets(self):
        name = 'AWS secrets found in response'
        host = self.helpers.analyzeRequest(self.request_response).getUrl()
        detail = 'Secrets to AWS were found in response'
        matches = []

        response = self.request_response.getResponse()

        for secret in self.secrets:
            matches += self.get_matches(
                response, bytearray(secret)
            )

        if (len(matches) > 0):
            return [ScanIssue(
                    self.request_response.getHttpService(),
                    host,
                    [self.callbacks.applyMarkers(
                        self.request_response, None, matches
                    )],
                    name,
                    detail,
                    'High'
                )
            ]
        return []

    def check_metadata_secrets(self, insertion_point):
        name = 'AWS secrets found in meta-data'
        host = self.helpers.analyzeRequest(self.request_response).getUrl()
        detail = ''
        schemes = ['', 'http://', 'https://']
        httpService = self.request_response.getHttpService()

        for scheme in schemes:
            payload = scheme + '169.254.169.254/latest/meta-data/' \
                + 'iam/security-credentials/'

            request = insertion_point.buildRequest(payload)

            checkRequestResponse = self.callbacks.makeHttpRequest(
                httpService, request
            )

            code = self.helpers.analyzeResponse(
                checkRequestResponse.getResponse()
            ).getStatusCode()

            body_off = self.helpers.analyzeResponse(
                checkRequestResponse.getResponse()
            ).getBodyOffset()

            # FIXME: we need someting better than that
            if code == 200:
                body = self.helpers.bytesToString(
                    checkRequestResponse.getResponse()[body_off:]
                )

                m = re.match('^(\S+)$', body)

                if m:
                    payload += m.group(1)
                else:
                    continue

                request = insertion_point.buildRequest(payload)

                checkRequestResponse = self.callbacks.makeHttpRequest(
                    httpService, request
                )

                response = checkRequestResponse.getResponse()

                matches = []
                for secret in self.secrets:
                    matches += self.get_matches(
                        response, bytearray(secret)
                    )

                if (len(matches) > 0):
                    detail = 'Target allows to access its instance ' \
                        + 'meta-data containing AWS secrets.'

                    return [ScanIssue(
                            self.request_response.getHttpService(),
                            host,
                            [self.callbacks.applyMarkers(
                                checkRequestResponse, None, matches
                            )],
                            name,
                            detail,
                            'High'
                        )
                    ]
        return []

    def get_matches(self, response, match):
        matches = []
        start = 0
        rlen = len(response)
        mlen = len(match)

        while start < rlen:
            start = self.helpers.indexOf(response, match, True, start, rlen)
            if start == -1:
                break
            matches.append(array('i', [start, start + mlen]))
            start += mlen

        return matches

class S3BucketScan(object):
    def __init__(self, request_response, callbacks, opts):
        self.request_response = request_response
        self.callbacks = callbacks
        self.helpers = self.callbacks.getHelpers()

        self.access_key = opts["aws_access_key"]
        self.secret_key = opts["aws_secret_key"]

        self.writeRequestResponse = None
        self.getRequestResponse = None

        self.sdk = False
        try:
            import boto3
            self.sdk = True
        except ImportError:
            print('Failed to load boto3 AWS SDK for Python! ' \
                + 'Some checks will be skipped without it. Install boto3 by ' \
                + 'running: pip install boto3 --target ~/path_to_your/bapp/' \
                + 'Lib\nIf you are on Mac OS and use homebrew check: ' \
                + 'https://stackoverflow.com/questions/135035/' \
                + 'python-library-path')

    def scan_S3_buckets(self, insertion_point):
        name = 'AWS S3 bucket in use'
        detail = ''
        host = self.request_response.getHttpService().getHost()
        s3host = host + '.s3.amazonaws.com'
        s3request = 'GET / HTTP/1.1\r\nHost: ' + s3host + '\r\n\r\n'
        region = 'unknown'
        issue = []

        # XXX: at the moment no need for SSL
        httpService = self.helpers.buildHttpService(s3host, 80, False)

        checkRequestResponse = self.callbacks.makeHttpRequest(
            httpService, self.helpers.stringToBytes(s3request)
        )

        code = self.helpers.analyzeResponse(
            checkRequestResponse.getResponse()
        ).getStatusCode()

        headers = self.helpers.analyzeResponse(
            checkRequestResponse.getResponse()
        ).getHeaders()

        for header in headers:
            if 'x-amz-bucket-region: ' in header:
                region = header[21:]

        if code == 200 or code == 307:
            detail = 'Target allows unauthenticated read-only access to' \
                + ' AWS S3 bucket located at <b>' + s3host + '</b>. ' \
                + 'Manual verification is required to determine if ' \
                + 'anyone can also store data in this bucket. Region ' \
                + 'for this bucket is <b>' + region + '</b>.'

            issue = [ScanIssue(
                    self.request_response.getHttpService(),
                    URL('http://' + host + ':80'),
                    [checkRequestResponse],
                    name,
                    detail,
                    'Medium'
            )]

            if self.chkUnauthBucketWrite(httpService):
                detail = 'Target allows unauthenticated read-write ' \
                    + 'access to AWS S3 bucket located at <b>' \
                    + s3host + '</b>. Region for this bucket is <b>' \
                    + region \
                    + '</b>.'

                issue = [ScanIssue(
                        self.request_response.getHttpService(),
                        URL('http://' + host + ':80'),
                        [self.writeRequestResponse,
                            self.getRequestResponse],
                        name,
                        detail,
                        'High'
                )]
            elif self.chkAuthBucketWrite(httpService, region):
                detail = 'Target allows authenticated read-write access' \
                    + 'to AWS S3 bucket located at <b>' + s3host \
                    + '</b>. Region for this bucket is <b>' + region \
                    + '</b>.'

                issue = [ScanIssue(
                        self.request_response.getHttpService(),
                        URL('http://' + host + ':80'),
                        [self.request_response],
                        name,
                        detail,
                        'High'
                )]
        elif code == 403:
            detail = 'Target uses AWS S3 bucket located at <b>' \
                + s3host + '</b> but public access is forbidden. In ' \
                + 'order to read or write data to this bucket one ' \
                + 'needs to know its AWS_ACCESS_KEY_ID and ' \
                + 'AWS_SECRET_ACCESS_KEY.'

            issue = [ScanIssue(
                    self.request_response.getHttpService(),
                    URL('http://' + host + ':80'),
                    [checkRequestResponse],
                    name,
                    detail,
                    'Information'
            )]

            if self.chkUnauthBucketWrite(httpService):
                detail = 'Target allows unauthenticated write-only ' \
                    + 'access to AWS S3 bucket located at <b>' \
                    + s3host + '</b>. Region for this bucket is <b>' \
                    + region \
                    + '</b>.'

                issue = [ScanIssue(
                        self.request_response.getHttpService(),
                        URL('http://' + host + ':80'),
                        [self.writeRequestResponse,
                            self.getRequestResponse],
                        name,
                        detail,
                        'High'
                )]
            elif self.chkAuthBucketWrite(httpService, region):
                detail = 'Target allows authenticated write-only access' \
                    + 'to AWS S3 bucket located at <b>' + s3host \
                    + '</b>. Region for this bucket is <b>' + region \
                    + '</b>.'

                issue = [ScanIssue(
                        self.request_response.getHttpService(),
                        URL('http://' + host + ':80'),
                        [self.request_response],
                        name,
                        detail,
                        'High'
                )]

        return issue

    # Analogic check for DELETE can be easily added
    def chkUnauthBucketWrite(self, httpService):
        s3host = httpService.getHost()
        s3request = 'PUT /tekcub HTTP/1.1\r\nHost: ' + s3host + '\r\n' \
            + 'Content-Length: 6\r\n\r\ntekcub\r\n'

        self.writeRequestResponse = self.callbacks.makeHttpRequest(
            httpService, self.helpers.stringToBytes(s3request)
        )

        s3request = 'GET /tekcub HTTP/1.1\r\nHost: ' + s3host + '\r\n\r\n'

        self.getRequestResponse = self.callbacks.makeHttpRequest(
            httpService, self.helpers.stringToBytes(s3request)
        )

        code = self.helpers.analyzeResponse(
             self.getRequestResponse.getResponse()
        ).getStatusCode()

        if code == 200:
            return True

        return False

    def chkAuthBucketWrite(self, httpService, region):
        response = ''

        if self.sdk:
            try:
                client = boto3.client(
                    's3',
                    aws_access_key_id = self.access_key,
                    aws_secret_access_key = self.secret_key,
                    # XXX: at the moment no need for SSL
                    endpoint_url = 'http://' + httpService.getHost(),
                    region_name = region
                )
                try:
                    response = client.list_buckets()
                except:
                    try: # hackety hack
                        for path in sys.path:
                            jythonPath = glob(path + '/jython*.jar')

                            if len(jythonPath) > 0:
                                classPathHacker().addFile(jythonPath[0])
                                break

                        response = client.list_buckets()
                    except Exception, e:
                        print('Exception in chkBucketWrite(): ' + str(e))
                        print('Failed to find and load required ' \
                            + 'modules. Set "Extender" > "Options" ' \
                            + '> "Python Environment" > "Folder for ' \
                            + 'loading modules (optional)" to point ' \
                            + 'on the same directory where the Jython ' \
                            + 'JAR archive is located.')
                        self.sdk = False
                        return False
            except Exception, e:
                print('Exception in chkBucketWrite(): ' + str(e))
                self.sdk = False
                return False

            # TODO: handle different responses, e.g. invalid
            # region/secrets etc.
            if len(response) > 0:
                print(response)
                try:
                    client.create_bucket(Bucket='tekcub')
                except Exception, e:
                    print('Exception in chkBucketWrite(): ' + str(e))
                    return False

                return True

        return False

class ScanIssue(IScanIssue):
    def __init__(self, http_service, url, request_response, name, severity, detail_msg):
        self.url_ = url
        self.http_service = http_service
        self.request_response = request_response
        self.name_ = name
        self.severity_ = severity
        self.detail_msg = detail_msg

    def getUrl(self):
        return self.url_

    def getHttpMessages(self):
        return self.request_response

    def getHttpService(self):
        return self.http_service

    @staticmethod
    def getRemediationDetail():
        return None

    def getIssueDetail(self):
        return self.detail_msg

    @staticmethod
    def getIssueBackground():
        return None

    @staticmethod
    def getRemediationBackground():
        return None

    @staticmethod
    def getIssueType():
        return 0

    def getIssueName(self):
        return self.name_

    def getSeverity(self):
        return self.severity_

    @staticmethod
    def getConfidence():
        return 'Certain'
