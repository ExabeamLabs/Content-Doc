#### Parser Content
```Java
{
Name = s-sonicwall-failed-vpn-login
  DataType = "failed-vpn-login"
  Conditions = [ """msg="User login failed""", "SSLVPN:", "id=sslvpn"]
  Fields = ${SonicwallParserTemplates.sonicwall-vpn-login.Fields} [
    """\smsg="({failure_reason}[^"]+)""""
  ]
}
sonicwall-vpn-login = {
  Vendor = Sonicwall
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\d\d:\d\d:\d\d ({host}[^\s]+)\sSSLVPN:""",
    """\stime="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\ssrc=({src_ip}[\da-fA-F\.:]+)""",
    """\sdst=({dest_ip}[\da-fA-F\.:]+)""",
    """\suser="({user}[^"]+)"""",
    """\sproto=({protocol}\S+)""",
    """\sdomain="({domain}[^"]+)"""",
    """\sportal="({realm}[^"]+)"""",
    """\sagent="({user_agent}[^"]+)"""",
    """\sduration=({session_duration}\d+)""",
    """\sbytesIn=({bytes_in}\d+)""",
    """\sbytesOut=({bytes_out}\d+)""",
    """\sbytesTotal=({bytes}\d+)"""
  ]

```