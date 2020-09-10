#### Parser Content
```Java
{
Name = syslog-cisco-cta-security-alert
  Vendor = Cisco
  Product = Cisco Advance Malware Protection (AMP)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """ tool=cta:tool-cta """, """ incidentTitle=""", """ cIP=""" ]
  Fields = [ 
    """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,3})Z\s+customer=""",
    """({host}cta)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """\sincidentId=({alert_id}\S+)""",
    """\sincidentTitle=({alert_name}\S.+?)\s+(\w+=|$)""",
    """\srisk=({alert_severity}\d+)""",
    """\sriskCategory=({alert_severity}\S.+?)\s+(\w+=|$)""",
    """\scIP=({src_ip}\S+)""",
    """\ssIP=({dest_ip}\S+)""",
    """\scsUrl=({malware_url}\S+)""",
    """\scUsername=({user}\S.+?)\s+(\w+=|$)""",
    """\sactivity=({additional_info}\S.+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```