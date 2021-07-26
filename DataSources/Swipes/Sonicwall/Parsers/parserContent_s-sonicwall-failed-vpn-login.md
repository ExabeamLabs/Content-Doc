#### Parser Content
```Java
{
Name = s-sonicwall-failed-vpn-login
  Product = Sonicwall
  DataType = "failed-vpn-login"
  Conditions = [ """msg="User login failed""", "SSLVPN:", "id=sslvpn"]
  Fields = ${SonicwallParserTemplates.sonicwall-vpn-login.Fields} [
    """\smsg="({failure_reason}[^"]{1,2000})""""
  ]
}
sonicwall-vpn-login = {
  Vendor = Sonicwall
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000})\sSSLVPN:""",
    """\stime="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\ssrc=({src_ip}[\da-fA-F\.:]{1,2000})""",
    """\sdst=({dest_ip}[\da-fA-F\.:]{1,2000})""",
    """\suser="({user}[^"]{1,2000})"""",
    """\sproto=({protocol}\S+)""",
    """\sdomain="({domain}[^"]{1,2000})"""",
    """\sportal="({realm}[^"]{1,2000})"""",
    """\sagent="({user_agent}[^"]{1,2000})"""",
    """\sduration=({session_duration}\d{1,100})""",
    """\sbytesIn=({bytes_in}\d{1,100})""",
    """\sbytesOut=({bytes_out}\d{1,100})""",
    """\sbytesTotal=({bytes}\d{1,100})"""
  ]

```