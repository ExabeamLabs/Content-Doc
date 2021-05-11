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
    """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
    """"_system_name":"({host}[^"]+)""",
    """"ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"]+)""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]+)""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"]+)""",
    """"query\\?"{1,20}:\\?"{1,20}({query}[^"]+)""",
    """"qtype_name\\?"{1,20}:\\?"{1,20}({query_type}[^"]+)""",
    """"rcode_name\\?"{1,20}:\\?"{1,20}({dns_response_code}[^"]+)""",
    """"answers\\?"{1,20}:\[({response}.+?)\]""",
    """"rejected\\?"{1,20}:({outcome}\w+)""",
  ]
}
```