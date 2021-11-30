#### Parser Content
```Java
{
Name = leef-pan-vpn-logout
  DataType = "vpn-logout"
  Conditions = [ """LEEF:""", """|Palo Alto Networks|""", """|PAN-OS Syslog Integration|""", """|gateway-logout-success|""", """|Type=GLOBALPROTECT|""" ]

leef-pan-vpn-event = {
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Splunk
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Fields = [
    """\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d\s({host}[\w\-.]{1,2000})""",
    """ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
    """usrName =(({domain}[^\\|]{1,2000})\\)?({user}[^|]{1,2000})""",
    """PrivateIP=({src_translated_ip}[A-Fa-f\d:.]{1,2000})""",
    """PublicIP=({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """Machinename=({src_host}[\w\-.]{1,2000})""",
    """EventID=({event_name}[^|]{1,2000})""",
    """Status=({outcome}[^|]{1,2000})"""
  
}
```