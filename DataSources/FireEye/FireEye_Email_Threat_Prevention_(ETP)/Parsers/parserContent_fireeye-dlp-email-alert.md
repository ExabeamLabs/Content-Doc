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
    """appliance:\s{0,100}({host}[^\s]{1,2000})""",
    """occurred:\s{0,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """\salert\s{0,100}\(id:({alert_id}[^,]{1,2000}),\s{0,100}name:({alert_type}[^\)]{1,2000})""",
    """severity:\s{0,100}({alert_severity}[^\s]{1,2000})""",
    """smtp-mail-from:\s{0,100}([^<]{1,2000}<)?({sender}[^@\s]{1,2000}@[^\s>]{1,2000})""",
    """smtp-to:\s{0,100}({recipient}[^@\s]{1,2000}@[^\s,]{1,2000})""",
    """\saction:\s{0,100}({outcome}[^\s]{1,2000})""",
    """\ssubject:\s{0,100}({subject}.+?)\s{1,100}src:""",
    """\stype:\s{0,100}({category}[^\s]{1,2000})\s{1,100}stype:""",
    """X-ETP-TRAFFIC-TYPE:\s{0,100}({direction}[^\s]{1,2000})""",
    """X-RECEIVED-IP:\s{0,100}({src_ip}[\da-fA-F:\.]{1,2000})""",
    """X-Message-ID:\s{0,100}({message_id}[^\s]{1,2000})""",
    """last-malware:\s{0,100}({alert_name}[^:]{1,2000}?)\s{1,100}protocol""",
    """\ssmtp-mail-from:.+?url:\s{0,100}({malware_url}.+?)\s{1,100}dst:""",
    """domain:\s{0,100}({domain}[^:]{1,2000}?)\s{1,100}smtp-mail-from:""",
    """md5sum:\s({md5}[^\s]{1,2000})""",
    """sha256:\s{1,100}({sha256}[^\s]{1,2000})"""
  ]
  DupFields = ["recipient->user_email"]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_type->description", "user_email->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "outcome->dlpActionTaken","host->dlpDeviceName"]
    NameTemplate = """FireEye DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```