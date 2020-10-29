#### Parser Content
```Java
{
Name = s-xml-windows-member-9
  DataType = "vpn-start"
  Conditions = [ "<EventID>2000</EventID>", "<Data Name='IPsecTrafficMode'>" ]
  Fields =${WinParserTemplates.s-xml-windows-member.Fields}[
    """<Data Name='RemoteUserAccount'>([^<>]+?\\)?(-|[^\$\s<>]+\$|({account}[^\s<>]+))"""
  ]
}
```