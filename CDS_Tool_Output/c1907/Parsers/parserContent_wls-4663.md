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
    """Computer="+({host}[^"]+)"""",
    """"({time}\d\d\d\d\-\d+\-\d+T\d\d:\d\d:\d\d)""",
    """EventID="+({event_code}[^"]+)"""",
    """EventRecordID="+({record_id}[^"]+)"""",
    """SubjectUserName="+({user}[^"]+)"""",
    """SubjectUserSid="+({user_sid}[^"]+)"""",
    """SubjectDomainName="+({domain}[^"]+)"""",
    """SubjectLogonId="+({logon_id}[^"]+)"""",
    """ObjectType="+({file_type}[^"]+)""",
    """ObjectName="+({file_path}[^"]+)""",
    """ObjectName="+.*\\({file_name}(?:[^\\:]+(?=\.))({file_ext}\.[^\\:]+)?|[^\\:]+)"+,\s*ObjectServer=""",
    """ObjectName="+(?:({file_parent}.+?)\\+[^\\]+)",""",
    """ProcessName="+({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
    """AccessList="({accesses}[^"]+)""",
    """AccessMask="({access_mask}[^"]+)"""
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```