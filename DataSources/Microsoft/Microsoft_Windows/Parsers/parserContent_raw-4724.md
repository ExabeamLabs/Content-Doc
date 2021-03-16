#### Parser Content
```Java
{
Name = raw-4724
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-password-reset"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "An attempt was made to reset an account's password" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """<\d+>(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(am\s+|pm\s+)?(::ffff:)?({host}[\w\-.]+)\s"""
      """<\d+>(?i)\w+\s*\d+\s*\d+:\d+:\d+\s+(am\s+|pm\s+)?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|10\.\.0\.01|({dest_host}[\w\-.]+))\s"""
      """({event_name}An attempt was made to reset an account's password)""",
      """Security,?\s*(rn=)?({record_id}[\d]+)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(,|\s+)(::ffff:)?({host}[\w\-\.]+)""",
      """(::ffff:)?((?i)KAFKA_CONNECT_SYSLOG|({host}[\w.\-]+))\s*:\s+An attempt was made to reset an account's password""",
      """({event_code}4724)""",
      """(::ffff:)?({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing""",
      """Computer(\w+)?["\s]*(:|=)\s*"?(::ffff:)?({host}[^"\s]+?)("|\s)""",
      """Computer : (::ffff:)?({host}[\w\-]+)""",
      """\w+\s*\d+\s\d+:\d+:\d+\s+(::ffff:)?(10\.\.0\.01|({host}[\w\-.]+))"""
      """Subject:[^=]+?Security ID:\s+(NT AUTHORITY\\SYSTEM|({user_sid}[^:]+?))\s+Account Name:""",
      """\s*Source Address:\s*(?:-|(::ffff:)?({src_ip}[^\s]+))\s*Source Port:""",
      """Subject:[^=]+?Account Name:\s+({user}[^:]+?)\s+Account Domain:\s+((?i)NT AUTHORITY|({domain}[^:]+?))\s+Logon ID""",
      """Logon ID:\s+({logon_id}[^\s]+)""",
      """Target Account[^=]+?Security ID:\s+(|({target_user_sid}[^:]+?))\s+Account Name:\s+(|({target_user}[^:]+?))\s+Account Domain:\s+({target_domain}[^",\s]+)"""
    ]
    DupFields=[ "host->dest_host" ]
  }
```