#### Parser Content
```Java
{
Name = s-carbonblack-security-alert
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard 
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"legacy_alert_id"""", """"threat_indicators"""", """"reason_code"""", """_threat_category"""", """"type":"CB_ANALYTICS"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """carbonblack,"({host}[^"]{1,2000}?)"""",
    """"{1,20}create_time"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}severity":\s{0,100}({alert_severity}[^,]{1,2000}?),""",
    """"{1,20}category"{1,20}:\s{0,100}"{1,20}({category}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}threat_id"{1,20}:\s{0,100}"{1,20}({threat_id}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}device_username"{1,20}:\s{0,100}"{1,20}(({user_email}[^@,"]{1,2000}@[^",]{1,2000})|(({domain}[^\\"]{1,2000}?)\\+)?({user}[^"]{1,2000}))"{1,20}""",
    """"{1,20}device_name"{1,20}:\s{0,100}"{1,20}(\w+\\+)?({host}[^."]{1,2000})""",
    """"{1,20}reason_code"{1,20}:\s{0,100}"{1,20}({alert_name}[^,]{1,2000}?)",""",
    """"{1,20}threat_indicators":[^\}\]]{0,2000}?"process_name"{1,20}:\s{0,100}"{1,20}({process_name}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}reason"{1,20}:\s{0,100}"{1,20}({additional_info}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}threat_indicators":[^\}\]]{0,2000}?"sha256"{1,20}:\s{0,100}"{1,20}({sha256}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}threat_indicators"{1,20}:[^\}\]]{0,2000}?"{1,20}ttps"{1,20}:\s{0,100}\["{1,20}({process}[^"]{1,2000}?)"{1,20}\]""",
    """"{1,20}policy_name"{1,20}:\s{0,100}"{1,20}({policy}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}state"{1,20}:\s{0,100}"{1,20}({state}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}type"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}legacy_alert_id"{1,20}:\s{0,100}"{1,20}({alert_id}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}org_key"{1,20}:\s{0,100}"{1,20}({primary_key}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}not_blocked_threat_category"{1,20}:\s{0,100}"{1,20}(UNKNOWN|({alert_type}[^"]{1,2000}?))"{1,20}""",
    """"{1,20}blocked_threat_category"{1,20}:\s{0,100}"{1,20}(UNKNOWN|({alert_type}[^"]{1,2000}?))"{1,20}""",
    """"{1,20}report_name"{1,20}:\s{0,100}"{1,20}({alert_name}[^,]{1,2000}?)",""",
    """"{1,20}report_id"{1,20}:\s{0,100}"{1,20}({alert_id}[^"]{1,2000}?)"{1,20}""",
    """"process_name"{1,20}:"{1,20}({process_name}[^"]{1,2000})""",
    """"threat_cause_actor_name"{1,20}:"{1,20}({process}({process_directory}[^"]{1,2000})\\({process_name}[^"]{1,2000}))"""",
    """device_internal_ip"{1,20}:"{1,20}({src_ip}[A-Fa-f.:\d]{1,2000})""",
    """"run_state":"({outcome}[^"]{1,2000})"""
  ]


}
```