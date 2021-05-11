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
    """exabeam_host=({host}[\w\-.]+)""",
    """2020/04/06:03:06:13({time}\d\d\d\d\/\d\d\/\d\d:\d\d:\d\d:\d\d)"""
    """User\s{1,100}({user}[^\s]+)"""
    """Vserver\s{1,100}(127.0.0.1|({host}[^:\s]+))"""
    """SSO is ON\s{0,100}:\s{0,100}({method}[^\s]+)\s{1,100}({object}[^\-\s]+)""",
    """SessionId:\s{1,100}({session_id}\d{1,100})"""
    """({event_name}HTTPREQUEST)""",
    """ahost=({src_host}[^\s]+)""",
 ]
}
```