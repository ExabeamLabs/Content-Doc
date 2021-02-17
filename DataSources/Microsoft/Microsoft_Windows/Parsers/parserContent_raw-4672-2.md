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
      """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
      """({event_code}4672)""",
      """({event_name}Special privileges assigned to new logon)""",
      """DetectTime=({time}\d+-\d+-\d+\s\d+:\d+:\d+)""",
      """ComputerName=({host}[^\s\=]+)\s+\w+=""",
      """EventType=({outcome}\w.+?)\s*\w+=""",
      """Account Name=\s*(-|SYSTEM|({user}[^\s\:\=]+?))[\s;]+""",
      """User=(?:(?i)null|({user}[^\s\=]+))\s+""",
      """Account Domain=\s*(-|({domain}[^\s\:\=]+?))[\s;]+""",
      """Security ID=\s*(|(({domain}[^\\\s\:\=]+)[\\]({user}[^\s\:\=]+))|({user_sid}[^\s\:\=]+?))\s+""",
      """Privileges=\s*({privileges}.+?)(,|\s*"|;|\s*$)""",
      """Logon ID=\s*({logon_id}[^\s\=]+)\s+""",
      """EventSource=({log_source}[^\s\=]+)\s*\w+="""
   ]
    DupFields = ["host->dest_host"]
 }
```