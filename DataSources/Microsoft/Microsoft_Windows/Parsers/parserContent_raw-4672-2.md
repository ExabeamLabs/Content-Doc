#### Parser Content
```Java
{
Name = raw-4672-2
   Vendor = Microsoft
   Product = Microsoft Windows
   Lms = Splunk
   DataType = "windows-privileged-access"
   TimeFormat = "yyyy-MM-dd HH:mm:ss"
   Conditions = [ """EventID=4672""", """Special privileges assigned to new logon""", """Privileges=""", """ComputerName=""" ]
   Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """({event_code}4672)""",
      """({event_name}Special privileges assigned to new logon)""",
      """DetectTime=({time}\d{1,100}-\d{1,100}-\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100})""",
      """ComputerName=({host}[^\s\=]{1,2000})\s{1,100}\w+=""",
      """EventType=({outcome}\w.+?)\s{0,100}\w+=""",
      """Account Name=\s{0,100}(-|SYSTEM|({user}[^\s\:\=]{1,2000}?))[\s;]{1,2000}""",
      """User=(?:(?i)null|({user}[^\s\=]{1,2000}))\s{1,100}""",
      """Account Domain=\s{0,100}(-|({domain}[^\s\:\=]{1,2000}?))[\s;]{1,2000}""",
      """Security ID=\s{0,100}(|(({domain}[^\\\s\:\=]{1,2000})[\\]({user}[^\s\:\=]{1,2000}))|({user_sid}[^\s\:\=]{1,2000}?))\s{1,100}""",
      """Privileges=\s{0,100}({privileges}.+?)(,|\s{0,100}"|;|\s{0,100}$)""",
      """Logon ID=\s{0,100}({logon_id}[^\s\=]{1,2000})\s{1,100}""",
      """EventSource=({log_source}[^\s\=]{1,2000})\s{0,100}\w+="""
   ]
    DupFields = ["host->dest_host"]
 }
```