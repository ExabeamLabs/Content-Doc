#### Parser Content
```Java
{
Name = raw-windows-account-4740
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-account-lockout"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["""Account That Was Locked Out"""]
  Fields = [
    """exabeam_host=(gcs-topic|({host}[\w\-.]{1,2000}))""",
    """"agent_hostname":"({host}[^"]{1,200})"""",
    """computer":"({host}[^"]{1,200})"""",
    """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?({host}[\w\-.]{1,2000})\s"""
    """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]{1,2000}))\s"""
    """({event_name}Account That Was Locked Out)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """({event_code}4740)""",
    """(?i)(((audit|success)( |_)(success|audit))|information)(\s{1,100}|,)(::ffff:)?({host}[\w.\-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)\s({host}[\w\-.]{1,2000})""",
    """(::ffff:)?({host}[^\/\s]{1,2000})\/Microsoft-Windows-Security-Auditing \(4740\)""",
    """"dhn":"(::ffff:)?({host}[^-"]{1,2000})""",
    """Computer : (::ffff:)?({host}[\w\-]{1,2000})""",
    """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?(::ffff:)?({host}.+?)("|\s)""",
    """"system_name":"(::ffff:)?({host}[^"]{1,2000})"""",
    """Security,?(\srn=|\s{1,100})?({record_id}\d{1,100})""",       
    """Subject:.+?Account Name:\s{1,100}({caller_user}.+?)\s{1,100}Account Domain:\s{1,100}(?=\w)({caller_domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Locked Out:\s{1,100}Security ID:\s{1,100}(%\{)?({user_sid}([\w\d\-]{1,2000}?)|([^\s]{1,2000}))\}?\s{1,100}Account Name:\s{1,100}(?=\w)({user}.+?)\s{1,100}Additional""",
    """Caller Computer Name:\s{1,100}(\\+)?(::ffff:)?({src_host}[^\#\s",<]{1,2000})""",
  ]
  DupFields=["host->dest_host", "caller_domain->domain" ]


}
```