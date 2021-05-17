#### Parser Content
```Java
{
Name = s-trusteer-epp-alert
  Vendor = IBM
  Product = IBM Endpoint Manager
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """IBM Security Trusteer Apex Advanced Malware Protection""" ]
  Fields = [ """exabeam_host=({host}[^\s]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """event_name=({alert_name}.+?)\s{1,100}event_id=({alert_id}[^\s]{1,2000})""",
    """severity=({alert_severity}\d{1,100})""",
    """local_ip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """computer_name=({src_host}[\w.\-]{1,2000})""",
    """external_ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """username=(?=\w+)({user}.+?)\s{1,100}(digitally_signed_by|target_ip)""",
    """suspicious_(item_details|process_path|file_path)=({malware_url}.+?)\s{1,100}suspicious_(item|process|file)"""
  ]
}
```