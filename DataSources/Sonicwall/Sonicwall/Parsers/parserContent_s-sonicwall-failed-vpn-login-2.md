#### Parser Content
```Java
{
Name = s-sonicwall-failed-vpn-login-2
  Product = Sonicwall
  DataType = "failed-vpn-login"
  Conditions = [ """ m=140 """, """id=""", """ usr=""", """ fw=""" , """Authentication failure"""]
  Fields = ${SonicwallParserTemplates.sonicwall-vpn-login.Fields} [
    """({outcome}Failed)"""
  ]
}
sonicwall-vpn-login = {
  Vendor = Sonicwall
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\d\d:\d\d:\d\d ({host}[^\s]+)\sSSLVPN:""",
    """\stime="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({src_port}\d{1,100}))?(:({src_interface}[^\s:]+))?(:({src_host}[^\s:]+))?""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d{1,100}))?(:({dest_interface}[^\s:]+))?(:({dest_host}[^\s:]+))?""",
    """\suser="\s{0,100}(({user_email}[^@"]+@[^\\\s"]+)|({user}[^\\\s"]+))""",
    """\susr="\s{0,100}(({user_email}[^@"]+@[^\\\s"]+)|({user}[^\\\s"]+))\s{0,100}"""",
    """\sproto=({protocol}\S+)""",
    """\sdomain="({domain}[^"]+)"""",
    """\sportal="({realm}[^"]+)"""",
    """\sagent="({user_agent}[^"]+)"""",
    """\sduration=({session_duration}\d{1,100})""",
    """\sbytesIn=({bytes_in}\d{1,100})""",
    """\sbytesOut=({bytes_out}\d{1,100})""",
    """\sbytesTotal=({bytes}\d{1,100})"""
  ]

```