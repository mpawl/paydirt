# paydirt

Paydirt will help you find dangling DNS entries in cloud provider IP address space. 

# Dependencies

Paydirt relies on external services:
1. Virus Total
1. Amazon AWS
1. Digital Ocean

API keys must be acquired for each of these services to use Pay Dirt. 

## Virus Total

A Virus Total API key is required to run Pay Dirt. Virus Total provides free API keys. [Instructions here](https://docs.virustotal.com/docs/please-give-me-an-api-key) to get a free Virus Total API key. 

Once your Virus Total API key is acquired, it must be populated in the `.env` file. The `.env` file must be stored in the same directory as `pd.py`. The entry in `.env` file should look like below:

`VT_API_KEY = '...'`

## Amazon AWS

The AWS CLI is required to run Pay Dirt. Amazon provides [Instructions here](https://docs.aws.amazon.com/cli/v1/userguide/cli-chap-install.html) to install AWS CLI. 

Once installed, you must configure AWS CLI with appropriate keys and minimum configuration. The Access Key must have permissions to Allocate and Release an Elastic IP. The snipets below outline a minimum configuration. 

```
cat ~/.aws/credentials
[default]
aws_access_key_id = ...
aws_secret_access_key = ...
```

```
cat ~/.aws/config
[default]
region=us-east-1
```

## Digital Ocean

If Digital Ocean functionality is desired, a Digital Ocean Personal Access Token is required. [Instructions here](https://docs.digitalocean.com/reference/api/create-personal-access-token/) to get a Digital Ocean Personal Access Token.

Once your DO Personal Access Token is acquired, it must be populated in the `.env` file. The `.env` similar to the Virus Total API key. The entry in `.env` file should look like below:

`DO_API_KEY = '...'`

# Installation

It is recommended to use a Python Virtual Environment (venv) for running Pay Dirt. Create and activate the venv as outlined below. 

```
python3 -m venv <virtual_environment_name>
source <path_to_venv>/bin/activate
```
Once the Python venv is installed and activated, install Python library dependencies. Pythong library dependencies are provided in a `requirements.txt` file. 

```
python3 -m pip install -r requirements.txt
```
# Usage

Below is the help screen for Pay Dirt, detailing the command line options. 

```
usage: pd.py [-h] [--count COUNT] [--log [LOG]] [--cloud {aws,do}]

options:
  -h, --help        show this help message and exit
  --count COUNT     Number of IPs to catch and test.
  --log [LOG]       Log file for output. By default, this is ./pd.log. You must have write permissions to the
                    specified file and enclosing directory. The file and enclosing directory[ies] must already exist.
  --cloud {aws,do}  Cloud provider to be used. Choices are AWS or Digital Ocean.
```

# Logging


