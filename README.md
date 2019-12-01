# AWS Extender Extended

AWS Extender Extended is a [BurpSuite](https://portswigger.net/burp/) extension combining the functionality of [AWS Extender](https://github.com/VirtueSecurity/aws-extender) and [AWS Security Checks](https://github.com/PortSwigger/aws-security-checks).

## Checks (partial list)

| Active |
| ------ |
| S3 buckets in use |
| S3 buckets unauthenticated read |
| S3 buckets unauthenticated write |
| S3 buckets authenticated read |
| S3 buckets authenticated write |
| AWS secrets accessible via metadata |

| Passive |
| ------- |
| AWS secrets returned in response |

## Getting Started
##### For general instructions on how to load BurpSuite extensions, please visit this [URL](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite).

#### Installing Dependencies
Both of [boto](https://github.com/boto/boto) and [boto3](https://github.com/boto/boto3) are required. You can install them using [pip](https://en.wikipedia.org/wiki/Pip_\(package_manager\)):

    $ pip install -r requirements.txt

#### Custom Environment Settings
1. Open the BurpSuite Extender tab.
2. Click "Options".
3. Set the "Folder for loading modules" setting to the path of your Python installation's [site-packages directory](https://docs.python.org/2/install/#how-installation-works).

#### Extension Settings
The settings tab provides the following settings:

| Setting           | Description                       | Required      |
|-------------------|:---------------------------------:|:-------------:|
| AWS Access Key    | Your AWS account access key ID    | True          |
| AWS Secret Key    | Your AWS account secret key       | True          |
| AWS Session Key   | A temporary session token         | False         |
| GS Access Key     | Your Google account access key ID | True          |
| GS Secret Key     | Your Google account secret key    | True          |
| Wordlist Filepath | A filepath to a list of filenames | False         |
| Passive Mode      | Perform passive checks only       | N/A           |

**Notes:**
* AWS keys can be obtained from your [AWS Management Console](https://console.aws.amazon.com/iam/home?#/security_credential). For Google Cloud, see [the documentation](https://cloud.google.com/storage/docs/migrating#keys).

* The extension will still provide minimal functionality (e.g., identifying buckets) even if none of the above requirements are satisfied.
