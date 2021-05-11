#### Parser Content
```Java
{
Name = paloalto-network-connection
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """,THREAT,url,"""]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """THREAT,[^,]+,[^,]+,({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z),({src_ip}[^,]*?),({dest_ip}[^,]*?),({src_translated_ip}[^,]+),({dest_translated_ip}[^,]+)""",
    """THREAT,url,([^,]*,){26}("{1,20})?.+?({web_domain}[a-z0-9\-]+\.[a-z0-9\-]{2,})[\\\/\s:"]"""
    """THREAT,([^,]*,){7}({rule}.+?)\s{0,100}
```