#### Parser Content
```Java
{
Name = raw-8004-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "MM/dd/yyyy HH:mm:ss"
    Conditions = [ """security policy Network Security:""", """Restrict NTLM:""", """EventCode=8004""" ]
    Fields = [
      """({event_name}Domain Controller Blocked Audit: Audit NTLM authentication to this domain controller)""",
      """({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d)""",
      """ComputerName=({host}[^\s]+)""",
      """({event_code}8004)""",
      """User name:\s+({user}[^\s]+)""",
      """Domain name:\s+(NULL|({domain}[^\s]+))""",
      """RecordNumber=({record_id}\d+)""",
      """Channel name:\s*({resource}.*?)\s+User name:""",
      """Workstation name:\s*\\?(NULL|({src_host}[\w\-.]+))\s+Secure Channel type:""",
      """security policy Network Security:\s*Restrict NTLM:\s*({policy}[^\.]+)""",
    ]
    DupFields = ["host->dest_host"]
  }
```