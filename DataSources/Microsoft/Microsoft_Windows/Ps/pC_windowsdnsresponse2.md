#### Parser Content
```Java
{
Name = windows-dns-response-2
  DataType = "dns-response"
  Conditions = [ """Query/Response=R""", """Flags (char codes)=""", """Question Type=""" ]

windows-dns = {
  Vendor = Microsoft
  Product = Microsoft Windows
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