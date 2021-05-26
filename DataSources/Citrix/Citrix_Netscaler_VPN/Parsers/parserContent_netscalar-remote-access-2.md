#### Parser Content
```Java
{
Name = netscalar-remote-access-2
 Vendor = Citrix
 Product = Citrix Netscaler VPN
 Lms = Direct
 TimeFormat = "MM/dd/yyyy:HH:mm:ss"
 DataType = "remote-access"
 Conditions = [ """|SSLVPN""" , """|HTTPREQUEST|""" ]
 Fields =[
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """2020/04/06:03:06:13({time}\d\d\d\d\/\d\d\/\d\d:\d\d:\d\d:\d\d)"""
    """User\s{1,100}({user}[^\s]{1,2000})"""
    """Vserver\s{1,100}(127.0.0.1|({host}[^:\s]{1,2000}))"""
    """SSO is ON\s{0,100}:\s{0,100}({method}[^\s]{1,2000})\s{1,100}({object}[^\-\s]{1,2000})""",
    """SessionId:\s{1,100}({session_id}\d{1,100})"""
    """({event_name}HTTPREQUEST)""",
    """ahost=({src_host}[^\s]{1,2000})""",
 ]
}
```