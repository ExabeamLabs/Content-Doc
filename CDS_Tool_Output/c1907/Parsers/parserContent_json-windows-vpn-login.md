#### Parser Content
```Java
{
Name = json-windows-vpn-login
  DataType = "vpn-start"
  Conditions = [ """"service":"vpn"""", """Virtual-Server""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"User-Name":"(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))""",
    """"Packet-Type":"({action}[^"]+)""",
    """"Client-IP-Address":"({src_ip}[a-fA-F\d.:]+)""",
    """"Client-Shortname":"({src_host}[^"]+)""",
    """"NAS-IP-Address":"({src_ip}[a-fA-F\d.:]+)""",
    """"Framed-IP-Address":"({dest_ip}[a-fA-F\d.:]+)""",
    """"hostname":"({host}[^"]+)""",
    """"status":"({outcome}[^"]+)""",
    """"realm":"({realm}[^"]+)""",
  ]
}
```