#### Parser Content
```Java
{
Name = s-mssql-database-query-al-xml
  Lms = Direct
  DataType = "database-query"
  Conditions = [ """>33205</EventID>""", """action_id:AL""" ]
  Fields = ${MicrosoftParserTemplates.s-mssql-database-query.Fields} [
    """\sserver_principal_name:({domain}[^\s]+)""",
    """\sserver_principal_name:(({domain}[^\\]+)\\)?({user}[^\s]+)\sserver_principal_sid""",
    """\sserver_principal_sid:({db_user_sid}[^\s]+)""",
  ]
}

${MicrosoftParserTemplates.s-mssql-database-query}{
  Name = s-mssql-database-query-dl
  DataType = "database-query"
  Conditions = [ """EventCode=33205""", """action_id:DL""" ]
}

${MicrosoftParserTemplates.s-mssql-database-query}{
  Name = s-mssql-database-query-dl-xml
  Lms = Direct
  DataType = "database-query"
  Conditions = [ """>33205</EventID>""", """action_id:DL""" ]
  Fields = ${MicrosoftParserTemplates.s-mssql-database-query.Fields} [
    """\sserver_principal_name:({domain}[^\s]+)""",
    """\sserver_principal_name:(({domain}[^\\]+)\\)?({user}[^\s]+)\sserver_principal_sid""",
    """\sserver_principal_sid:({db_user_sid}[^\s]+)""",
  ]
}

${MicrosoftParserTemplates.s-mssql-database-query}{
  Name = s-mssql-database-query-sl
  DataType = "database-query"
  Conditions = [ """EventCode=33205""", """action_id:SL""" ]
}

${MicrosoftParserTemplates.s-mssql-database-query}{
  Name = s-mssql-database-query-sl-xml
  Lms = Direct
  DataType = "database-query"
  Conditions = [ """>33205</EventID>""", """action_id:SL""" ]
  Fields = ${MicrosoftParserTemplates.s-mssql-database-query.Fields} [
    """\sserver_principal_name:({domain}[^\s]+)""",
    """\sserver_principal_name:(({domain}[^\\]+)\\)?({user}[^\s]+)\sserver_principal_sid""",
    """\sserver_principal_sid:({db_user_sid}[^\s]+)""",
  ]
}

{
  Name = xml-microsoft-dns-query
  Vendor = Microsoft
  Product = Microsoft Windows DNSServer
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<Data Name='QNAME'>""", """<Data Name='QTYPE'>""", """<Data Name='Flags'>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)""",
    """<Computer>({host}.+?)<\/Computer>""",
    """<Data Name='InterfaceIP'>({dest_ip}[A-Fa-f:\d.]+)""",
    """<Data Name='Source'>({src_ip}[A-Fa-f:\d.]+)""",
    """<Data Name='Port'>({src_port}\d+)""",
    """<Data Name='QNAME'>({query}.+?({top_query}\w+.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)\.))<\/Data>""",
    """<Data Name='QTYPE'>({query_type}.+?)<\/Data>""",
    """<Data Name='Flags'>({query_flags}.+?)<\/Data>""",
    """<Data Name='BufferSize'>({bytes}\d+)<\/Data>""",
  ]
}
```