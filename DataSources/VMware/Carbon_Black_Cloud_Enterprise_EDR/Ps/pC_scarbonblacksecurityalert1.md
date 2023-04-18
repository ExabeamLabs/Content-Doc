#### Parser Content
```Java
{
Name = s-carbonblack-security-alert-1
  Vendor = VMware
  Product = Carbon Black Cloud Enterprise EDR 
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"Carbon Black"""", """"threat_id"""", """"threat_cause_actor_name"""", """"type":"WATCHLIST"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"{1,20}create_time"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}severity":\s{0,100}({alert_severity}[^,]{1,2000}?),""",
    """"{1,20}category"{1,20}:\s{0,100}"{1,20}({category}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}threat_id"{1,20}:\s{0,100}"{1,20}({threat_id}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}device_username"{1,20}:\s{0,100}"{1,20}(({user_email}[^@,"]{1,2000}@[^",]{1,2000})|(({domain}[^\\"]{1,2000}?)\\+)?({user}[^"]{1,2000}))"{1,20}""",
    """"{1,20}device_name"{1,20}:\s{0,100}"{1,20}(\w+\\+)?({host}[^."]{1,2000})""",
    """"{1,20}threat_indicators":[^\}\]]{0,2000}?"process_name"{1,20}:\s{0,100}"{1,20}({process_name}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}reason"{1,20}:\s{0,100}"{1,20}({additional_info}[^,]{1,2000}?)"{1,20

}
```