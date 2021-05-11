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
    """"@timestamp"\s{0,100}:\s{0,100}"({time}.+?)"""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]+\sSkyformation""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}.+?)"""",
    """({event_code}4742)""",
    """({event_name}A computer account was changed.)""",
    """SubjectDomainName"\s{0,100}:\s{0,100}"({domain}[^"]+)""",
    """SubjectUserName"\s{0,100}:\s{0,100}"({user}[^"]+)""" 
    """SubjectLogonId"\s{0,100}:\s{0,100}"({logon_id}[^"]+)""",
    """TargetUserName"\s{0,100}:\s{0,100}"({target_user}[^"]+)""",
    """ServicePrincipalNames"\s{0,100}:\s{0,100}"({attribute}[^"]+)"""
    """TargetDomainName"\s{0,100}:\s{0,100}"({object_dn}[^"]+)""",
    """TargetUserName"\s{0,100}:\s{0,100}"({src_host}[^\s$]+)\$"""
  ]
  DupFields = [ "host-> dest_host"]
}
```