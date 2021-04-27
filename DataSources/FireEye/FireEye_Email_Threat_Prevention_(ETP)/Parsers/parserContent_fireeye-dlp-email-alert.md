#### Parser Content
```Java
{
Name = fireeye-dlp-email-alert
  Vendor = FireEye
  Product = FireEye Email Threat Prevention (ETP)
  Lms = Syslog
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """alert (id:""", """X-ETP-TRAFFIC-TYPE:""", """fenotify-""", """alert-url:""", """X-RECEIVED-IP:""" ]
  Fields = [
    """appliance:\s*({host}[^\s]+)""",
    """occurred:\s*({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """\salert\s*\(id:({alert_id}[^,]+),\s*name:({alert_type}[^\)]+)""",
    """severity:\s*({alert_severity}[^\s]+)""",
    """smtp-mail-from:\s*([^<]+<)?({sender}[^@\s]+@[^\s>]+)""",
    """smtp-to:\s*({recipient}[^@\s]+@[^\s,]+)""",
    """\saction:\s*({outcome}[^\s]+)""",
    """\ssubject:\s*({subject}.+?)\s+src:""",
    """\stype:\s*({category}[^\s]+)\s+stype:""",
    """X-ETP-TRAFFIC-TYPE:\s*({direction}[^\s]+)""",
    """X-RECEIVED-IP:\s*({src_ip}[\da-fA-F:\.]+)""",
    """X-Message-ID:\s*({message_id}[^\s]+)""",
    """last-malware:\s*({alert_name}[^:]+?)\s+protocol""",
    """\ssmtp-mail-from:.+?url:\s*({malware_url}.+?)\s+dst:""",
    """domain:\s*({domain}[^:]+?)\s+smtp-mail-from:""",
    """md5sum:\s({md5}[^\s]+)""",
    """sha256:\s+({sha256}[^\s]+)"""
  ]
  DupFields = ["recipient->user_email"]
}
```