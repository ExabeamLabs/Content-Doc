#### Parser Content
```Java
{
Name = cef-palo-alto-networks-firewall-deny
  DataType = "network-connection"
  Conditions = [ """Palo Alto Networks|PAN-OS|""", """|deny|TRAFFIC|""" ]
}

${PaloAltoParserTemplates.cef-palo-alto-networks-firewall} {
  Name = cef-palo-alto-networks-firewall-end
  DataType = "network-connection"
  Conditions = [ """|Palo Alto Networks|PAN-OS|""", """end|TRAFFIC|""" ]
}

${PaloAltoParserTemplates.cef-palo-alto-networks-firewall} {
  Name = cef-palo-alto-networks-setip
  DataType = "vpn-set-ip"
  Conditions = [ """|Palo Alto Networks|PAN-OS|""", """|client switch to SSL tunnel mode succeeded|""" ]
  Fields = ${PaloAltoParserTemplates.cef-palo-alto-networks-firewall.Fields}[
    """Private IP:\s*({src_translated_ip}[a-fA-F\d.:]+[^\.\s])""",
  ]
}

{
  Name = palo-alto-networks-setip
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "vpn-set-ip"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotectgateway-switch-succ,""", """gateway client switch to SSL tunnel mode succeeded""" ]
  Fields = [
    """({host}[\w.\-]+)\s+\d+,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]*,SYSTEM,globalprotect,""",
    """Private IP:\s*({src_translated_ip}[a-fA-F\d.:]+[^\."])""",
    """User name:\s+({user}[^,]+)"""
  ]
}
```