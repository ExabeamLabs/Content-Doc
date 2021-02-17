#### Parser Content
```Java
{
Name = exalms-4742
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSZ" 
  Conditions = ["""@timestamp":""", """A computer account was changed.""" , """Service Principal Names:"""]
  Fields = [
    """"@timestamp"\s*:\s*"({time}.+?)"""",
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
```