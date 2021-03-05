#### Parser Content
```Java
{
Name = bro-dns-response
  Vendor = Bro
  Product = Bro
  Lms = Direct
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"rcode""", """"rcode_name""" ]
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"+:\\?"+({conn_id}[^"]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}[a-fA-F\d.:]+)""",
    """"proto\\?"+:\\?"+({protocol}[^"]+)""",
    """"query\\?"+:\\?"+({query}[^"]+)""",
    """"qtype_name\\?"+:\\?"+({query_type}[^"]+)""",
    """"rcode_name\\?"+:\\?"+({dns_response_code}[^"]+)""",
    """"answers\\?"+:\[({response}.+?)\]""",
    """"rejected\\?"+:({outcome}\w+)""",
  ]
}
```