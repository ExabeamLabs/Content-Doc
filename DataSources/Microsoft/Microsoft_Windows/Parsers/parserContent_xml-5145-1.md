#### Parser Content
```Java
{
Name = xml-5145-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "share-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>5145<""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """<Computer>({host}[\w\-.]+)""",
    """<Computer>(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|({host}[\w\-.]+))""",
    """({event_code}5145)""",
    """<EventRecordID>({record_id}[^<]+)""",
    """'SubjectUserSid'>({user_sid}[^"\s<]+)<""",
    """'SubjectUserName'>({user}[^"\s<]+)<""",
    """'SubjectDomainName'>({domain}[^"\s<]+)<""",
    """'SubjectLogonId'>({logon_id}[^"\s<]+)<""",
    """'ObjectType'>({file_type}[^<]+)<""",
    """'IpAddress'>({src_ip}[A-Fa-f:\d.]+)<""",
    """'IpPort'>({src_port}\d{1,100})""",
    """'ShareName'>(?:\\+\*\\+)?({share_name}.+?)<""",
    """'ShareLocalPath'>(?:[\\\?]+)?(?:\s{0,100}|({share_path}({d_parent}.*?)({d_name}[^\\]+?)))<""",
    """'RelativeTargetName'>(({f_parent}.*?)({file_name}[^\\:]+?(\.({file_ext}[^\\.]+?))?))<""",
    """'ObjectType'>({file_type}[^<]+)<""",
    """'ObjectType'>({file_type}[^<]+)<""",
  ]
}
```