#### Parser Content
```Java
{
Name = windows-dns-query-2
  DataType = "dns-query"
  Conditions = [ """Query/Response=Q""", """Flags (char codes)=""", """Question Type=""" ]
  Fields = ${MicrosoftParserTemplates.windows-dns.Fields}[
     """\sQuestion Name=({query}[^\t"]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))"""
  ]
  DupFields = [ "dest_ip->dest_host" ]
}
```