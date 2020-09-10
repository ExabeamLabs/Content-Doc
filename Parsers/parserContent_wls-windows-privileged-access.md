#### Parser Content
```Java
{
Name = wls-windows-privileged-access
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""LogType="WLS"""", """EventID="467"""]
    Fields = [
      """Computer="+({host}[^".]+)""",
      """"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """EventID="+({event_code}[^"]+)"""",
      """Keywords="+({outcome}[^"]+)"""",
      """SubjectUserName="+({user}[^"]+)"""",
      """SubjectDomainName="+({domain}[^"]+)"""",
      """SubjectLogonId="+({logon_id}[^"]+)"""",
      """ProcessName="+(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^"]+)))"+,""",
      """PrivilegeList="+({privileges}[^"]+)"""",
      """AccessMask="+({accesses}[^"]+)"""",
      """ObjectName="+(?:-|({object}[^"]+))"""",
      """ObjectType="+(?:-|({object_type}[^"]+))"""",
      """ObjectServer="+(?:-|({object_server}[^"]+))""""
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```