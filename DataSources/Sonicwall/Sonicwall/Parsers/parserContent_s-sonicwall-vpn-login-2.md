#### Parser Content
```Java
{
Name = s-sonicwall-vpn-login-2
  Product = Sonicwall
  DataType = "vpn-login"
  Conditions = [ """ m=1080 """, """id=""", """ usr=""", """ fw=""","""sslvpn"""]
  Fields = ${SonicwallParserTemplates.sonicwall-vpn-login.Fields} [
    """({outcome}allowed)"""
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
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({src_port}\d{1,100}))?(:({src_interface}[^\s:]{1,2000}))?(:({src_host}[^\s:]{1,2000}))?""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d{1,100}))?(:({dest_interface}[^\s:]{1,2000}))?(:({dest_host}[^\s:]{1,2000}))?""",
    """\suser="\s{0,100}(({user_email}[^@"]{1,2000}@[^\\\s"]{1,2000})|({user}[^\\\s"]{1,2000}))""",
    """\susr="\s{0,100}(({user_email}[^@"]{1,2000}@[^\\\s"]{1,2000})|({user}[^\\\s"]{1,2000}))\s{0,100}"""",
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