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
     """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
     """id\.orig_h="({src_ip}[a-fA-F\d.:]+)""",
     """id\.orig_p="({src_port}\d{1,100})""",
     """id\.resp_h="({dest_ip}[a-fA-F\d.:]+)""",
     """id\.resp_p="({dest_port}\d{1,100})""",
     """proto="({protocol}[^"]+)""",
     """trans_id="({query_id}\d{1,100})""",
     """query="({query}[^"\\]+)""",
     """qtype_name="({query_type}[^"\\]+)""",
     """rejected="({outcome}[^"]+)""",
     """rcode="({rcode}[^"]+)""",
     """answers="({answers}[^"]+)""",
     """answers=({response}.+?)\s\w+=(\s|")"""
  ] 
}
```