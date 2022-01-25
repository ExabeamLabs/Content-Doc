#### Parser Content
```Java
{
Name = xml-microsoft-dns-query
  Vendor = Microsoft
  Product = Windows DNSServer
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<Data Name ='QNAME'>""", """<Data Name ='QTYPE'>""", """<Data Name ='Flags'>""" ]
  Fields = [
    """TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)""",
    """Computer>({host}.+?)<\/Computer>""",
    """EventID>({event_code}\d{1,100})<\/EventID>""",
    """Execution ProcessID='({pid}\d{1,100})""",
    """<Data Name ='XID'>({query_id}\d{1,100})""",
    """ThreadID='({thread_id}[^\']{1,2000})""",
    """<Data Name ='InterfaceIP'>({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """<Data Name ='Source'>({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """<Data Name ='Port'>({src_port}\d{1,100})""",
    """Name ='QNAME'>({query}[^<]{1,2000}?({top_query}\w{1,2000}.(?i)\w{1,2000}))\.?<\/Data>""",
    """<Data Name ='QTYPE'>({query_type}.+?)<\/Data>""",
    """<Data Name ='Flags'>({query_flags}.+?)<\/Data>""",
    """<Data Name ='BufferSize'>({bytes}\d{1,100})<\/Data>""",
  ]


}
```