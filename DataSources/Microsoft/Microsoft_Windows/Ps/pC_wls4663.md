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
    """Computer="{1,20}({host}[^"]{1,2000})"""",
    """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
    """EventID="{1,20}({event_code}[^"]{1,2000})"""",
    """EventRecordID="{1,20}({record_id}[^"]{1,2000})"""",
    """SubjectUserName="{1,20}({user}[^"]{1,2000})"""",
    """SubjectUserSid="{1,20}({user_sid}[^"]{1,2000})"""",
    """SubjectDomainName="{1,20}({domain}[^"]{1,2000})"""",
    """SubjectLogonId="{1,20}({logon_id}[^"]{1,2000})"""",
    """ObjectType="{1,20}({file_type}[^"]{1,2000})""",
    """ObjectName="{1,20}({file_path}[^"]{1,2000})""",
    """ObjectName="{1,20}.*\\({file_name}(?:[^\\:]{1,2000}(?=\.))({file_ext}\.[^\\:]{1,2000})?|[^\\:]{1,2000})"{1,20}
```