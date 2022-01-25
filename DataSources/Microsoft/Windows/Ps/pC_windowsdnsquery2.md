#### Parser Content
```Java
{
Name = windows-dns-query-2
  DataType = "dns-query"
  Conditions = [ """Query/Response=Q""", """Flags (char codes)=""", """Question Type=""" ]
  Fields = ${MicrosoftParserTemplates.windows-dns.Fields}[
     """\sQuestion Name =({query}[^\t"]{1,2000}\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))"""
  ]

windows-dns = {
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  IsHVF = true
  TimeFormat = "M/dd/yyyy'\tTime='H:mm:ss a"
  Fields = [
    """<\d{1,100}>\w+ \d{1,100} \d\d:\d\d:\d\d ({host}[\w.\-]{1,2000})""",
    """\sDate=({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\t+Time=\d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """\sThread ID=({thread_id}[^\t]{1,2000})""",
    """\sUDP\/TCP indicator=({protocol}[^\t]{1,2000})""",
    """\sSend\/Receive indicator=({activity}[^\t]{1,2000})""",
    """\sRemote IP=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sXid \(hex\)=({query_id}[^\t]{1,2000})""",
    """\sFlags \(char codes\)=({query_flags}[^\t]{1,2000})""",
    """\sResponseCode=({dns_response_code}[^\t]{1,2000})""",
    """\sQuestion Type=({query_type}[^\t]{1,2000})""",
    """\sQuestion Name =({query}[^\t"]{1,2000})"""
  
}
```