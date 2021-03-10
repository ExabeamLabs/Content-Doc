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
```