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
windows-dns = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  IsHVF = true
  TimeFormat = "M/dd/yyyy'\tTime='H:mm:ss a"
  Fields = [
    """<\d+>\w+ \d+ \d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """\sDate=({time}\d+\/\d+\/\d\d\d\d\t+Time=\d+:\d+:\d+ (am|AM|pm|PM))""",
    """\sThread ID=({thread_id}[^\t]+)""",
    """\sUDP\/TCP indicator=({protocol}[^\t]+)""",
    """\sSend\/Receive indicator=({activity}[^\t]+)""",
    """\sRemote IP=({dest_ip}[a-fA-F\d.:]+)""",
    """\sXid \(hex\)=({query_id}[^\t]+)""",
    """\sFlags \(char codes\)=({query_flags}[^\t]+)""",
    """\sResponseCode=({dns_response_code}[^\t]+)""",
    """\sQuestion Type=({query_type}[^\t]+)""",
    """\sQuestion Name=({query}[^\t"]+)"""
  ]

```