#### Parser Content
```Java
{
Name = infoblox-bloxone-dns-response 
  Vendor = Infoblox BloxOne
  Product = Infoblox BloxOne
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""|Infoblox|""", """app=DNS""", """InfobloxDNSView=""", """InfobloxDNSQType=""" ]
  Fields = [
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """src=(\s|({src_ip}[a-fA-F\d.:]+))""",
     """dst=(\s|({dest_ip}[a-fA-F\d.:]+))""",
     """spt=(\s|({src_port}\d+))""",
     """proto=(\s|({protocol}[^\s]+))""",
     """app=({app}[^\s]+)""",
     """InfobloxDNSRCode=({dns_response_code}[^\s]+)\s""",
     """InfobloxDNSQType=(\s|({query_type}[^\s]+))""",
     """destinationDnsDomain=(\s|({query}[^\s]+))""",
     """msg=(\s|({additional_info}.+?));\s\.\s32768""",
  ]
}
```