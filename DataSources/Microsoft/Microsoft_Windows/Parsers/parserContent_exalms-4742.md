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
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]{1,2000}\sSkyformation""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}.+?)"""",
    """({event_code}4742)""",
    """({event_name}A computer account was changed.)""",
    """SubjectDomainName"\s{0,100}:\s{0,100}"({domain}[^"]{1,2000})""",
    """SubjectUserName"\s{0,100}:\s{0,100}"({user}[^"]{1,2000})""" 
    """SubjectLogonId"\s{0,100}:\s{0,100}"({logon_id}[^"]{1,2000})""",
    """TargetUserName"\s{0,100}:\s{0,100}"({target_user}[^"]{1,2000})""",
    """ServicePrincipalNames"\s{0,100}:\s{0,100}"({attribute}[^"]{1,2000})"""
    """TargetDomainName"\s{0,100}:\s{0,100}"({object_dn}[^"]{1,2000})""",
    """TargetUserName"\s{0,100}:\s{0,100}"({src_host}[^\s$]{1,2000})\$"""
  ]
  DupFields = [ "host-> dest_host"]
}
```