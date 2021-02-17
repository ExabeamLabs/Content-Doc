#### Parser Content
```Java
{
Name = cef-bromium-file-read
  Vendor = Bromium
  Product = Bromium Secure Platform
  Conditions = [ """|Bromium, Inc.|vSentry|""", """suser=""", """|vSentry isolated a file download|""" ]
  Fields = ${BromiumParserTemplates.cef-bromium-file-operations.Fields} [
    """({accesses}download)"""
  ]
}
```