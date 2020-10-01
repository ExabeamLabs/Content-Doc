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
     """ts="({time}\d+)""",
     """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
     """id\.orig_h="({src_ip}[a-fA-F\d.:]+)""",
     """id\.orig_p="({src_port}\d+)""",
     """id\.resp_h="({dest_ip}[a-fA-F\d.:]+)""",
     """id\.resp_p="({dest_port}\d+)""",
     """proto="({protocol}[^"]+)""",
     """trans_id="({query_id}\d+)""",
     """query="({query}[^"\\]+)""",
     """qtype_name="({query_type}[^"\\]+)""",
     """rejected="({outcome}[^"]+)""",
     """rcode="({rcode}[^"]+)""",
     """answers="({answers}[^"]+)""",
     """answers=({response}.+?)\s\w+=(\s|")"""
  ] 
}
```