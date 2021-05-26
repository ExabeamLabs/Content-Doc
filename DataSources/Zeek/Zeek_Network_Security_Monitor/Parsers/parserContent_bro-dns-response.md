#### Parser Content
```Java
{
Name = bro-dns-response
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"rcode""", """"rcode_name""" ]
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"_system_name":"({host}[^"]{1,2000})""",
    """"ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"]{1,2000})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]{1,2000})""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"]{1,2000})""",
    """"query\\?"{1,20}:\\?"{1,20}({query}[^"]{1,2000})""",
    """"qtype_name\\?"{1,20}:\\?"{1,20}({query_type}[^"]{1,2000})""",
    """"rcode_name\\?"{1,20}:\\?"{1,20}({dns_response_code}[^"]{1,2000})""",
    """"answers\\?"{1,20}:\[({response}.+?)\]""",
    """"rejected\\?"{1,20}:({outcome}\w+)""",
  ]
}
```