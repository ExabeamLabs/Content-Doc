#### Parser Content
```Java
{
Name = windows-xml-4742
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<EventID>4742</EventID>""", """<Data Name ='TargetSid'>""", """<Data Name ='TargetUserName'>""", """<Message>A computer account was changed""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,20}Z)""",
    """<Message>({event_name}A computer account was changed)""",
    """<Computer>({host}[\w\-.]{1,2000})<""",
    """<EventID>({event_code}4742)<""",
    """<Data Name ='TargetUserName'>({target_user}[^<]{1,2000})<""",
    """<Data Name ='TargetDomainName'>({object_dn}[^<]{1,2000})<""",
    """<Data Name ='SubjectUserName'>({user}[^<]{1,2000})<""",
    """<Data Name ='SubjectDomainName'>({domain}[^<]{1,2000})<""",
    """<Data Name ='SubjectLogonId'>({logon_id}[^<]{1,2000})<""",
    """<Data Name ='UserPrincipalName'>(-|({attribute}[^<]{1,2000}))<"""
  ]
  DupFields = [ "host->dest_host"]


}
```