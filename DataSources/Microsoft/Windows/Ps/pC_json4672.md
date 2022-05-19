#### Parser Content
```Java
{
Name = json-4672
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss" 
    Conditions = ["""4672""", """"PrivilegeList":""""]
    Fields = [
      """({event_name}Special privileges assigned to new logon)""", 
      """"EventReceivedTime":\s{0,100}({time}\d{1,100})""",
      """"TimeCreated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"Computer":"({host}[^"]{1,2000})"""",
      """"timestamp":\s{0,100}({time}\d{1,100})""",
      """"EventTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"(Hostname|MachineName)":"({host}[^"]{0,2000})""",
      """({event_code}4672)""",
      """"(Event|Entry)Type":"({outcome}[^"]{1,2000})""",
      """"SubjectUserName":"({user}[^"]{0,2000})""",
      """"SubjectDomainName":"({domain}[^"]{0,2000})""",
      """"SubjectLogonId":"({logon_id}[^"]{0,2000})""",
      """"PrivilegeList":"({privileges}[^\\"]{0,2000})""",
      """"Keywords":"({outcome}[^"]{1,2000})"""
    ]
    DupFields = ["host->dest_host"]
  

}
```