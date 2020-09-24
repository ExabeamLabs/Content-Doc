#### Parser Content
```Java
{
Name = cef-palo-alto-networks-setip
  DataType = "vpn-set-ip"
  Conditions = [ """|Palo Alto Networks|PAN-OS|""", """|client switch to SSL tunnel mode succeeded|""" ]
  Fields = ${PaloAltoParserTemplates.cef-palo-alto-networks-firewall.Fields}[
    """Private IP:\s*({src_translated_ip}[a-fA-F\d.:]+[^\.\s])""",
  ]
}
```