#### Parser Content
```Java
{
Name = bro-ssl-activity-2
  Product = Bro
  DataType = "authentication-successful"
  Conditions = [ """dataset""", """"ssl"""", """zeek""", """type""", """established""" ]
  Fields = ${BroParserTemplates.bro-activity-1.Fields}[
    """"+server"+.+?name"+:"+({server}[^"]+)""",
    """zeek"+.+?established"+:({outcome}[^,]+)""",
    """zeek"+.+?version"+:"+({version}[^"]+)"+,"+cipher"+:"+({auth_method}[^"]+)"""
    ]
}
```