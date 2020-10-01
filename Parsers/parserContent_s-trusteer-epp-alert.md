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
  Fields = [ """exabeam_host=({host}[^\s]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """event_name=({alert_name}.+?)\s+event_id=({alert_id}[^\s]+)""",
    """severity=({alert_severity}\d+)""",
    """local_ip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """computer_name=({src_host}[\w.\-]+)""",
    """external_ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """username=(?=\w+)({user}.+?)\s+(digitally_signed_by|target_ip)""",
    """suspicious_(item_details|process_path|file_path)=({malware_url}.+?)\s+suspicious_(item|process|file)"""
  ]
}
```