This subdirectory is composed of two files:
- rules_parser.py
- ten_logs_sample

ten_log_sample is a logfile produced by an Amazon Kinesis Data Firehose and delivered to an S3 bucket.
The file has no extension and it contains one JSON object per line, each representing a single request analized by the WAFv2.

rules_parser is a python script that scans a log file and partition the requests based on the WebACL rule that was triggered by that request. 
Since this script is been designed to analize the log files during a configuration of the rules of the webACL, hence the rules behaviour is ovverided to COUNT instead of blocking the requests, one requests might trigger more than one rule.

More information concerning WebACL rules can be found in the official AWS documentation:

#WebACL rule and rule group evaluation
https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-processing.html

#Fields of the log files 
https://docs.aws.amazon.com/waf/latest/developerguide/logging.html#logging-fields

#AWS Managed rules groups
https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
