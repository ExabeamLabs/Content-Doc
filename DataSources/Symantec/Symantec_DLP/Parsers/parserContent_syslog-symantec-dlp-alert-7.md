#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert-7
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Syslog
  DataType = "dlp-alert"
  TimeFormat = "MMM dd, yyyy HH:mm:ss a"
  Conditions = [ """Incident_Snapshot: """, """Endpoint_Machine: """, """Incident_ID: """, """Policy: """ ]
  Fields = [
    """({host}[^\s]+)\s*Incident_Snapshot:""",
    """Occurred:\s*({time}\w+ \d+, \d\d\d\d \d+:\d+:\d+ (?i)(am|pm))""",
    """Machine_IP:\s*({dest_ip}[a-fA-F:\.\d]+)""",
    """Severity:\s*({alert_severity}[^,]+)""",
    """Incident_ID:\s*({alert_id}\d+)""",
    """Status:\s*(N\/A|({status}[^,]+))""",
    """Endpoint_Username:\s*(N\/A|(({domain}[^\\,]+)\\+)?({user}[^,]+))""",
    """Endpoint_Machine:\s*(N\/A|({dest_host}[^,]+))""",
    """Protocol:\s*(N\/A|({protocol}[^,]+))""",
    """Recipients:\s*(N\/A|Unknown|({recipients}({recipient}[^@]+@[^,]+)[^:]*),[^:]+Subject:)""",
    """Subject:\s*(N\/A|({subject}[^,]+?))\s*,""",
    """Sender:\s*(N\/A|({sender}[^@]+@[^,]+)),[^:]+Recipients:""",
    """Policy:\s*({alert_name}[^,]+)""",
    """File_Full_Path:\s*(N\/A|(|({file_path}({file_parent}[^"]*?[\\\/]*)(|({file_name}[^\\\/"]*?(\.({file_ext}[^\\\/\.\s"]*))?)))))"*\s*$""",
    """(?i)recipients:\s*[^@]+@({external_domain}[^,"@]+)("|,|\s*$)""",
    """(?i)Incident_Snapshot:\s*\w+:\/+[^\s]*?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]+(\.(com|corp|upc|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))"""
  ]
  DupFields = [ "sender->user_email", "recipient->external_address", "recipients->target"]
}
```