#### Parser Content
```Java
{
Name = raw-windows-account-4740
        Vendor = Microsoft
        Product = Microsoft Windows
        Lms = Direct
        DataType = "windows-account-lockout"
        TimeFormat = "MMM dd HH:mm:ss yyyy"
        Conditions = ["Account That Was Locked Out"]
        Fields = [
          """exabeam_host=({host}[\w\-.]+)""",
          """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?({host}[\w\-.]+)\s"""
          """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))\s"""
          """({event_name}Account That Was Locked Out)""",
        """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
        """({event_code}4740)""",
        """(?i)(((audit|success)( |_)(success|audit))|information)(\s{1,100}|,)(::ffff:)?({host}[\w.\-]+)""",
        """(::ffff:)?({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing \(4740\)""",
        """"dhn":"(::ffff:)?({host}[^-"]+)""",
        """Computer : (::ffff:)?({host}[\w\-]+)""",
        """Computer(\w+)?["\s]*(:|=)\s{0,100}"?(::ffff:)?({host}.+?)("|\s)""",
        """"system_name":"(::ffff:)?({host}[^"]+)"""",
        """Security,?(\srn=|\s{1,100})?({record_id}\d{1,100})""",       
        """Subject:.+?Account Name:\s{1,100}({caller_user}.+?)\s{1,100}Account Domain:\s{1,100}(?=\w)({caller_domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]+)""",
        """Locked Out:\s{1,100}Security ID:\s{1,100}(%\{)?({user_sid}([\w\d\-]+?)|([^\s]+))\}?\s{1,100}Account Name:\s{1,100}(?=\w)({user}.+?)\s{1,100}Additional""",
        """Caller Computer Name:\s{1,100}(\\+)?(::ffff:)?({src_host}[^\#\s",<]+)""",
        ]
        DupFields=["host->dest_host", "caller_domain->domain" ]
 }
```