#### Parser Content
```Java
{
Name = wls-windows-privileged-access
    Vendor = Microsoft
    Product = Windows
    Lms = Splunk
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""LogType="WLS"""", """EventID="467"""]
    Fields = [
      """Computer="{1,20}({host}[^".]{1,2000})""",
      """"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]{1,2000})"""",
      """Keywords="{1,20}({outcome}[^"]{1,2000})"""",
      """SubjectUserName="{1,20}({user}[^"]{1,2000})"""",
      """SubjectDomainName="{1,20}({domain}[^"]{1,2000})"""",
      """SubjectLogonId="{1,20}({logon_id}[^"]{1,2000})"""",
      """ProcessName="{1,20}(?: |({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^"]{1,2000})))"{1,20},""",
      """PrivilegeList="{1,20}({privileges}[^"]{1,2000})"""",
      """AccessMask="{1,20}({accesses}[^"]{1,2000})"""",
      """ObjectName="{1,20}(?:-|({object}[^"]{1,2000}))"""",
      """ObjectType="{1,20}(?:-|({object_type}[^"]{1,2000}))"""",
      """ObjectServer="{1,20}(?:-|({object_server}[^"]{1,2000}))""""
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```