#### Parser Content
```Java
{
Name = exalms-4742
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""@timestamp":""", """A computer account was changed.""" , """Service Principal Names:"""]
  Fields = [
    """"@timestamp"\s*:\s*"({time}.+?)"""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s({host}[^\s]+)\sSkyformation""",
    """"computer_name"\s*:\s*"({host}.+?)"""",
    """({event_code}4742)""",
    """({event_name}A computer account was changed.)""",
    """SubjectDomainName"\s*:\s*"({domain}[^"]+)""",
    """SubjectUserName"\s*:\s*"({user}[^"]+)""" 
    """SubjectLogonId"\s*:\s*"({logon_id}[^"]+)""",
    """TargetUserName"\s*:\s*"({target_user}[^"]+)""",
    """ServicePrincipalNames"\s*:\s*"({attribute}[^"]+)"""
    """TargetDomainName"\s*:\s*"({object_dn}[^"]+)""",
    """TargetUserName"\s*:\s*"({src_host}[^\s$]+)\$"""
  ]
  DupFields = [ "host-> dest_host"]
}

{
  Name = exalms-4662
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""@timestamp":""", """An operation was performed on an object""" , """ObjectName""", """computer_name"""]
  Fields = [
    """({event_name}An operation was performed on an object)""",
    """"@timestamp"\s*:\s*"({time}.+?)"""",
    """"computer_name"\s*:\s*"({host}.+?)"""",
    """ObjectServer":"({object_class}.+?)"""",
    """ObjectName":"({object}[^"]+)"""",
    """ObjectType":"({activity_type}.+?)"""",
    """SubjectUserName":"({user}.+?)"""",
    """SubjectLogonId":"({logon_id}[^"]+)"""",
    """SubjectDomainName":"({domain}[^"]+)"""",
    """OperationType":"({action}[^"]+)"""",
    """Properties":"({properties}[^"]+)"""",
    """"AdditionalInfo"+:"+(-|({attribute}[^"]+))"""",
    """"keywords":\["({outcome}[^"]+)"\]""",
    """({event_code}4662)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```