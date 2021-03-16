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
          """<\d+>(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(am\s+|pm\s+)?(::ffff:)?({host}[\w\-.]+)\s"""
          """<\d+>(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(am\s+|pm\s+)?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))\s"""
          """({event_name}Account That Was Locked Out)""",
        """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
        """({event_code}4740)""",
        """(?i)(((audit|success)( |_)(success|audit))|information)(\s+|,)(::ffff:)?({host}[\w.\-]+)""",
        """(::ffff:)?({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing \(4740\)""",
        """"dhn":"(::ffff:)?({host}[^-"]+)""",
        """Computer : (::ffff:)?({host}[\w\-]+)""",
        """Computer(\w+)?["\s]*(:|=)\s*"?(::ffff:)?({host}.+?)("|\s)""",
        """"system_name":"(::ffff:)?({host}[^"]+)"""",
        """Security,?(\srn=|\s+)?({record_id}\d+)""",       
        """Subject:.+?Account Name:\s+({caller_user}.+?)\s+Account Domain:\s+(?=\w)({caller_domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
        """Locked Out:\s+Security ID:\s+(%\{)?({user_sid}([\w\d\-]+?)|([^\s]+))\}?\s+Account Name:\s+(?=\w)({user}.+?)\s+Additional""",
        """Caller Computer Name:\s+(\\+)?(::ffff:)?({src_host}[^\#\s",<]+)""",
        ]
        DupFields=["host->dest_host", "caller_domain->domain" ]
 }
```