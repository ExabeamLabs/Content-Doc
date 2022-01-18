#### Parser Content
```Java
{
Name = s-nac-logon-2
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "epoch"
  Conditions = [ """CISE_Passed_Authentications""", """|Cisco|Cisco ISE|""", """CEF:""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """ahost=({host}[^\s]{1,2000})"""
    """shost=({src_host}[^\s]{1,2000})""",
    """({event_name}CISE_Passed_Authentications)""",
    """suser=({user}[^\s]{1,2000})""",
    """dhost=({dest_host}[^\s]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """dst=({auth_server}[A-Fa-f:\d.]{1,2000})""",
    """dpt=({dest_port}\d{1,100})""",
    """Cisco ISE\|(|[^\|]{1,2000})\|({event_code}\d{1,100})\|""",
    """deviceSeverity=({severity}[^\s]{1,2000})""",
    """cs1=({auth_method}[^\s]{1,2000})""",
    """ad.User=({user}[^\s]{1,2000})""",
    """NetworkDeviceName\\*=({network}[^,\s]{1,2000})"""
  ]
  DupFields = ["dest_host->auth_server"]


}
```