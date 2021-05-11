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
      """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
      """({event_code}4672)""",
      """({event_name}Special privileges assigned to new logon)""",
      """DetectTime=({time}\d{1,100}-\d{1,100}-\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100})""",
      """ComputerName=({host}[^\s\=]+)\s{1,100}\w+=""",
      """EventType=({outcome}\w.+?)\s{0,100}\w+=""",
      """Account Name=\s{0,100}(-|SYSTEM|({user}[^\s\:\=]+?))[\s;]+""",
      """User=(?:(?i)null|({user}[^\s\=]+))\s{1,100}""",
      """Account Domain=\s{0,100}(-|({domain}[^\s\:\=]+?))[\s;]+""",
      """Security ID=\s{0,100}(|(({domain}[^\\\s\:\=]+)[\\]({user}[^\s\:\=]+))|({user_sid}[^\s\:\=]+?))\s{1,100}""",
      """Privileges=\s{0,100}({privileges}.+?)(,|\s{0,100}"|;|\s{0,100}$)""",
      """Logon ID=\s{0,100}({logon_id}[^\s\=]+)\s{1,100}""",
      """EventSource=({log_source}[^\s\=]+)\s{0,100}\w+="""
   ]
    DupFields = ["host->dest_host"]
 }
```