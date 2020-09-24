#### Parser Content
```Java
{
Name = netscalar-remote-access-2
 Product =Netscaler VPN
 Vendor = Citrix
 Lms = Direct
 TimeFormat = "MM/dd/yyyy:HH:mm:ss"
 DataType = "remote-access"
 Conditions = [ """|SSLVPN""" , """|HTTPREQUEST|""" ]
 Fields =[
    """exabeam_host=({host}[\w\-.]+)""",
    """2020/04/06:03:06:13({time}\d\d\d\d\/\d\d\/\d\d:\d\d:\d\d:\d\d)"""
    """User\s+({user}[^\s]+)"""
    """Vserver\s+(127.0.0.1|({host}[^:\s]+))"""
    """SSO is ON\s*:\s*({method}[^\s]+)\s+({object}[^\-\s]+)""",
    """SessionId:\s+({session_id}\d+)"""
    """({event_name}HTTPREQUEST)""",
    """ahost=({src_host}[^\s]+)""",
 ]
}
```