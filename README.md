# aws-security-group-tester
## What it is
This script will verify that AWS security groups allow, or deny, traffic according to a set of rules. The main purpose is to be able to verify complex configurations with multiple security groups per instance with simple statements.

## Usage
### AWS setup
The script uses the config and credentials from `aws cli`, so in order to use the script you'll need to create an access key and secret in AWS for your account and make sure
you can perform `describe instances` and `describe security_groups`.

At this time only the default profile is supported.

### Basic usage
```python checkSecurityGroups.py```
When run without any parameters the script will look for a file called `expected_rules.json` with expected rules defined. 
If found the script will proceed to fetch instances from AWS and verify that the configured security groups follows the defined rules.
If all is fine the script will exit without output, if a rule fails the verification output like below will be printed and the script will exit with code `1`.
```Allow from 0.0.0.0/0 to Jenkins tcp/0-65535 = False```

Verbose output can be switched on by using `-v`, this will currently only give output like above but with the addition of rules that pass the test.

Rules can be read from a specified file or from a directory with json-files with the `--expected-rules` switch.
```
python checkSecurityGroups.py --expected-rules rules.json
python checkSecurityGroups.py --expected-rules rules/
```

Similary can security-groups be read from json-files, instead of from the running configuration in AWS by specifying `--security-groups`.
```
python checkSecurityGroups.py --security-groups securityGroups.json
python checkSecurityGroups.py --security-groups securityGroups/
```
Note that if an instance use security groups not read from file, these will be fetched from AWS.

## Rules file(s)
The rule files is json-files following the pattern

```
[
  {
    "Source":"NAME",
    "Destination":"NAME",
    "ProtocolAndRange":"protocol/low-high",
    "IsAllowed": BOOLEAN
  }
]
```
`Source` and `Destination` should correspond to values of a tag `Name` on the EC2 instances, or an ip-address or network in CIDR notation. `ProtocolAndRange` is the protocol and a port range, single port values is not supported at this time (for a single port, low and high must be set to the same value). `IsAllowed` states if the traffic should be allowed or not.

```
[
  { //(1)
    "Source": "Foo",
    "Destination": "Bar",
    "ProtocolAndRange": "tcp\/22-22",
    "IsAllowed": true
  },
  { //(2)
    "Source": "192.168.0.2\/32",
    "Destination": "Foo",
    "ProtocolAndRange": "tcp\/22-22",
    "IsAllowed": true
  },
  { //(3)
    "Source": "192.168.0.0\/24",
    "Destination": "Bar",
    "ProtocolAndRange": "tcp\/80-80",
    "IsAllowed": true
  },
  { //(4)
    "Source": "Bar",
    "Destination": "0.0.0.0\/0",
    "ProtocolAndRange": "tcp\/0-65535",
    "IsAllowed": false
  }

]
```
Rundown of the above:
1. From the EC2-instance with the tag `Name` set to `Foo`, allow SSH to the instance with the `Name`-tag set to `Bar`
1. Allow SSH from the ip `192.168.0.2` to instance `Foo`
1. Allow HTTP from the network `192.168.0.0/24` to instance `Bar`
1. Deny outbound connections from `Bar` to any host on any port (except responses)

## Wildcards
`Source` and `Destination` can be set to `*` which mean "any instance". The sample rule below will check that no instance is open for incoming traffic on all ports from any host.
```
{
   "Source": "0.0.0.0/0",
   "Destination": "*",
   "ProtocolAndRange": "tcp\/0-65535",
   "IsAllowed": false
}
```


## TODO
- Single port values (i.e. 22 instead of 22-22)
- Service names instead of portnumbers (i.e. ssh instead of 22)
- Support for multiple IAM profiles
