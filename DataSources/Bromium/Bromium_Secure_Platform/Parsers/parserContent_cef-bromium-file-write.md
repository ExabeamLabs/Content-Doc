#### Parser Content
```Java
{
Name = cef-bromium-file-write
  Vendor = Bromium
  Product = Bromium Secure Platform
  Conditions = [ """|Bromium, Inc.|vSentry|""", """suser=""", """|vSentry detected file upload|""" ]
  Fields = ${BromiumParserTemplates.cef-bromium-file-operations.Fields} [
    """({accesses}upload)"""
  ]
}
```