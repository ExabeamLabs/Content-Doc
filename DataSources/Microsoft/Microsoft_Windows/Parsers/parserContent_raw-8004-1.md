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
      """User name:\s{1,100}({user}[^\s]+)""",
      """Domain name:\s{1,100}(NULL|({domain}[^\s]+))""",
      """RecordNumber=({record_id}\d{1,100})""",
      """Channel name:\s{0,100}({resource}.*?)\s{1,100}User name:""",
      """Workstation name:\s{0,100}\\?(NULL|({src_host}[\w\-.]+))\s{1,100}Secure Channel type:""",
      """security policy Network Security:\s{0,100}Restrict NTLM:\s{0,100}({policy}[^\.]+)""",
    ]
    DupFields = ["host->dest_host"]
  }
```