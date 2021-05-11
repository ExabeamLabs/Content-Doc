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
      """Computer="{1,20}({host}[^".]+)""",
      """"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """Keywords="{1,20}({outcome}[^"]+)"""",
      """SubjectUserName="{1,20}({user}[^"]+)"""",
      """SubjectDomainName="{1,20}({domain}[^"]+)"""",
      """SubjectLogonId="{1,20}({logon_id}[^"]+)"""",
      """ProcessName="{1,20}(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^"]+)))"{1,20}
```