#### Parser Content
```Java
{
Name = q-pan-vpn-setip
  DataType = "vpn-set-ip"
  Conditions = [ "subtype=globalprotect","globalprotect","Palo Alto Networks", "client configuration generated" ]
  Fields = ${PAParserTemplates.q-pan-vpn-parser.Fields} [
    """Private IP:\s?({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```