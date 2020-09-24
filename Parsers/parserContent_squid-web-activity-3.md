#### Parser Content
```Java
{
Name = squid-web-activity-3
  Vendor = Squid
  Product = Squid
  Lms = Direct
  DataType = "web-activity"
  TimeFormat ="epoch"
  Conditions = [ """ (squid): """ ]
  Fields = [
    """({host}\S+)\s\(squid\):\s+({time}[^\.]+)[\.\d]+\s+\d+\s({src_ip}[\da-fA-F\.:]+)\s(\w+\/)?({result_code}\d+)\s({bytes_out}\d+)\s({method}\S+)\s(({full_url}[^:]+:\/\/[^\s]+)|({web_domain}[^:\s]+)(:({dest_port}\d+))?)\s(-|({user}\S+))\s(\S+\/)?({dest_ip}[\da-fA-F\.:]+)"""
  ]
}
```