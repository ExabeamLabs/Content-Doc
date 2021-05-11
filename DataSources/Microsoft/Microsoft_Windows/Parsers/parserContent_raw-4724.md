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
      """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?({host}[\w\-.]+)\s"""
      """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|10\.\.0\.01|({dest_host}[\w\-.]+))\s"""
      """({event_name}An attempt was made to reset an account's password)""",
      """Security,?\s{0,100}(rn=)?({record_id}[\d]+)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(,|\s{1,100})(::ffff:)?({host}[\w\-\.]+)""",
      """(::ffff:)?((?i)KAFKA_CONNECT_SYSLOG|({host}[\w.\-]+))\s{0,100}:\s{1,100}An attempt was made to reset an account's password""",
      """({event_code}4724)""",
      """(::ffff:)?({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing""",
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?(::ffff:)?({host}[^"\s]+?)("|\s)""",
      """Computer : (::ffff:)?({host}[\w\-]+)""",
      """(?i)\w+\s{0,100}\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(10\.\.0\.01|am|pm|({host}[\w\-.]+))""",
      """Subject:[^=]+?Security ID:\s{1,100}(NT AUTHORITY\\SYSTEM|({user_sid}[^:]+?))\s{1,100}Account Name:""",
      """\s{0,100}Source Address:\s{0,100}(?:-|(::ffff:)?({src_ip}[^\s]+))\s{0,100}Source Port:""",
      """Subject:[^=]+?Account Name:\s{1,100}({user}[^:]+?)\s{1,100}Account Domain:\s{1,100}((?i)NT AUTHORITY|({domain}[^:]+?))\s{1,100}Logon ID""",
      """Logon ID:\s{1,100}({logon_id}[^\s]+)""",
      """Target Account[^=]+?Security ID:\s{1,100}(|({target_user_sid}[^:]+?))\s{1,100}Account Name:\s{1,100}(|({target_user}[^:]+?))\s{1,100}Account Domain:\s{1,100}({target_domain}[^",\s]+)"""
    ]
    DupFields=[ "host->dest_host" ]
  }
```