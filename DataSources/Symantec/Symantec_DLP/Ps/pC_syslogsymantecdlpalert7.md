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
    """({host}[^\s]{1,2000})\s{0,100}Incident_Snapshot:""",
    """Occurred:\s{0,100}({time}\w+ \d{1,100}, \d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (?i)(am|pm))""",
    """Machine_IP:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000})""",
    """Severity:\s{0,100}({alert_severity}[^,]{1,2000})""",
    """Incident_ID:\s{0,100}({alert_id}\d{1,100})""",
    """Status:\s{0,100}(N\/A|({status}[^,]{1,2000}))""",
    """Endpoint_Username:\s{0,100}(N\/A|(({domain}[^\\,]{1,2000})\\+)?({user}[^,]{1,2000}))""",
    """Endpoint_Machine:\s{0,100}(N\/A|({dest_host}[^,]{1,2000}))""",
    """Protocol:\s{0,100}(N\/A|({protocol}[^,]{1,2000}))""",
    """Recipients:\s{0,100}(N\/A|Unknown|({recipients}({recipient}[^@]{1,2000}@[^,]{1,2000})[^:]{0,2000}),[^:]{1,2000}Subject:)""",
    """Subject:\s{0,100}(N\/A|({subject}[^,]{1,2000}?))\s{0,100},""",
    """Sender:\s{0,100}(N\/A|({sender}[^@]{1,2000}@[^,]{1,2000})),[^:]{1,2000}Recipients:""",
    """Policy:\s{0,100}({alert_name}[^,]{1,2000})""",
    """File_Full_Path:\s{0,100}(N\/A|(|({file_path}({file_parent}[^"]{0,2000}?[\\\/]{0,2000})(|({file_name}[^\\\/"]{0,2000}?(\.({file_ext}[^\\\/\.\s"]{0,2000}))?)))))"{0,20}\s{0,100}$""",
    """(?i)Incident_Snapshot:\s{0,100}({full_url}[^,]{0,2000})""",
    """(?i)recipients:\s{0,100}[^@]{1,2000}@({external_domain}[^,"@]{1,2000})("|,|\s{0,100}$)""",
  ]
  DupFields = [ "sender->user_email", "recipient->external_address", "recipients->target"]
}
```