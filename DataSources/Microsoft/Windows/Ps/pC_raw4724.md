#### Parser Content
```Java
{
Name = raw-4724
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-password-reset"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "An attempt was made to reset an account's password" ]
    Fields = [
      """exabeam_host=(gcs-topic|({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w.\-]{1,2000}))))""",
      """"agent_hostname":"({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[^"]{1,200})))"""",
      """"computer":"({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[^"]{1,200})))"""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
      """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?({host}[\w\-.]{1,2000})\s"""
      """<\d{1,100}>(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am\s{1,100}|pm\s{1,100})?(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|10\.\.0\.01|({dest_host}[\w\-.]{1,2000}))\s"""
      """({event_name}An attempt was made to reset an account's password)""",
      """Security,?\s{0,100}(rn=)?({record_id}[\d]{1,2000})""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(,|\s{1,100})(::ffff:)?({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w\-\.]{1,2000})))""",
      """(::ffff:)?((?i)KAFKA_CONNECT_SYSLOG|({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w.\-]{1,2000}))))\s{0,100}:\s{1,100}An attempt was made to reset an account's password""",
      """({event_code}4724)""",
      """(::ffff:)?({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[^\/\s]{1,2000})))\/Microsoft-Windows-Security-Auditing""",
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?(::ffff:)?({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[^"\s]{1,2000}?)))("|\s)""",
      """Computer : (::ffff:)?({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w\-]{1,2000})))""",
      """(?i)\w+\s{0,100}\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(10\.\.0\.01|am|pm|({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w\-.]{1,2000}))))""",
      """Subject:[^=]{1,2000}?Security ID:\s{1,100}(NT AUTHORITY\\SYSTEM|({user_sid}[^:]{1,2000}?))\s{1,100}Account Name:""",
      """\s{0,100}Source Address:\s{0,100}(?:-|(::ffff:)?({src_ip}[^\s]{1,2000}))\s{0,100}Source Port:""",
      """Subject:[^=]{1,2000}?Account Name:\s{1,100}({user}[^:]{1,2000}?)\s{1,100}Account Domain:\s{1,100}((?i)NT AUTHORITY|({domain}[^:]{1,2000}?))\s{1,100}Logon ID""",
      """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
      """Target Account[^=]{1,2000}?Security ID:\s{1,100}(|({target_user_sid}[^:]{1,2000}?))\s{1,100}Account Name:\s{1,100}(|({target_user}[^:]{1,2000}?))\s{1,100}Account Domain:\s{1,100}({target_domain}[^",\s]{1,2000})"""
    ]
  

}
```