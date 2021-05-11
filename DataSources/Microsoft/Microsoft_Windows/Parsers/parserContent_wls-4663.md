#### Parser Content
```Java
{
Name = wls-4663
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4663"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """LogType="WLS"""", """EventID="4663"""" ]
  Fields = [
    """({event_name}An attempt was made to access an object)""",
    """Computer="{1,20}({host}[^"]+)"""",
    """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
    """EventID="{1,20}({event_code}[^"]+)"""",
    """EventRecordID="{1,20}({record_id}[^"]+)"""",
    """SubjectUserName="{1,20}({user}[^"]+)"""",
    """SubjectUserSid="{1,20}({user_sid}[^"]+)"""",
    """SubjectDomainName="{1,20}({domain}[^"]+)"""",
    """SubjectLogonId="{1,20}({logon_id}[^"]+)"""",
    """ObjectType="{1,20}({file_type}[^"]+)""",
    """ObjectName="{1,20}({file_path}[^"]+)""",
    """ObjectName="{1,20}.*\\({file_name}(?:[^\\:]+(?=\.))({file_ext}\.[^\\:]+)?|[^\\:]+)"{1,20}
```