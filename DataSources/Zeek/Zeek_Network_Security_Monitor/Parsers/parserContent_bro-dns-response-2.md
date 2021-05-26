#### Parser Content
```Java
{
Name = bro-dns-response-2
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "dns-query"
  TimeFormat = "epoch"
  Conditions = ["""id.orig_h="""", """id.resp_h="""", """query="""", """qtype_name="""]
  Fields = [
     """ts="({time}\d{1,100})""",
     """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
     """id\.orig_h="({src_ip}[a-fA-F\d.:]{1,2000})""",
     """id\.orig_p="({src_port}\d{1,100})""",
     """id\.resp_h="({dest_ip}[a-fA-F\d.:]{1,2000})""",
     """id\.resp_p="({dest_port}\d{1,100})""",
     """proto="({protocol}[^"]{1,2000})""",
     """trans_id="({query_id}\d{1,100})""",
     """query="({query}[^"\\]{1,2000})""",
     """qtype_name="({query_type}[^"\\]{1,2000})""",
     """rejected="({outcome}[^"]{1,2000})""",
     """rcode="({rcode}[^"]{1,2000})""",
     """answers="({answers}[^"]{1,2000})""",
     """answers=({response}.+?)\s\w+=(\s|")"""
  ] 
}
```