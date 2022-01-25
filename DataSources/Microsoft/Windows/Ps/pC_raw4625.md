#### Parser Content
```Java
{
Name = raw-4625
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = ["An account failed to log on", "Failure Reason"]
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\s({host}[\w-.]{1,2000})\s{0,100}Microsoft-Windows-Security-Auditing""",
      """EVENT_HOST="{1,100}({host}[\w.-]{1,2000})"""",
      """({event_name}An account failed to log on)""",
      """({event_code}4625)""",
      """\s({time}[a-zA-Z]{3} \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """({time}\d{1,4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,100}|(\+|\-)\d\d:\d\d))""",
      """(?i):\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]{1,2000}))""",
      """Subject(:|=).+?Account Name(:|=)\s{0,100}(-|({caller_user}[^\s@]{1,2000}?))[\s;]{0,2000}Account Domain(:|=)""",
      """Subject(:|=).+?Account Domain(:|=)\s{0,100}(-|({caller_domain}[^:;]{1,2000}?))[\s;]{0,2000}Logon ID(:|=)""",
      """Logon Type(:|=)\s{0,100}({logon_type}[\d]{1,2000})""",
      """Account For[\s;]{0,2000}Which Logon Failed(:|=)[\s;]{0,2000}Security ID(:|=)\s{0,100}([\/\\]{0,9}NULL SID|({user_sid}[^=:]{1,2000}?))[\s;]{0,2000}Account Name""",
      """Logon Failed(:|=).+?Account Name(:|=)\s{0,100}(-|\+{1,20}|SYSTEM|d2\/|({user_email}[^\s@;]{1,2000}?@[^\s@;]{1,2000}?)|({user}[^\s@]{1,2000}?))[\s;]{0,2000}Account Domain(:|=)""",
      """Logon Failed(:|=).+?Account Domain(:|=)\s{0,100}(|-|\?|({domain}[^\s]{1,2000}?))[\s;]{0,2000}Failure Information""",
      """Sub Status(:|=)\s{0,100}({result_code}[^\s;]{1,2000}?)[\s;]{0,2000}Process Information(:|=)""",
      """Workstation Name(:|=)\s{0,100}(?:-|(::ffff:)?({src_host_windows}[^\s;]{1,2000}))[\s;]{0,2000}Source Network Address(:|=)""",
      """Source Network Address(:|=)\s{0,100}(?:-|(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))[\s;]{0,2000}Source Port(:|=)""",
      """Logon Process(:|=)\s{0,100}({auth_process}[^\s;]{1,2000})[\s;]{0,2000}Authentication Package(:|=)""",
      """Authentication Package(:|=)\s{0,100}({auth_package}[^\s;]{1,2000}?)[\s;]{0,2000}Transited Services(:|=)""",
      """(?i):\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|\d{1,100}|({dest_host}[\w\-.]{1,2000})))\s""",
      """(EventType|EVENT_TYPE)="({outcome}[^"]{1,2000})"""
    ]
    DupFields = ["host->dest_host","src_host_windows->src_host"]
  

}
```