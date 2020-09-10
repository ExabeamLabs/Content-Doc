#### Parser Content
```Java
{
Name = pfsense-network-connection-failed
  Vendor = pfSense
  Product = pfSense
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """filterlog:""", """,match,block,""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """filterlog:(?:[^,]*,){4}({dest_interface}[^,]*),({activity}[^,]*),({outcome}[^,]*),({direction}[^,]*),(?:[^,]*,){8}({protocol}(tcp|udp)),[^,]*,({src_ip}[^,]*),({dest_ip}[^,]*),({src_port}[^,]*),({dest_port}[^,]*),""",
    """filterlog:(?:[^,]*,){7}in,(?:[^,]*,){8}(tcp|udp),(?:[^,]*,){5}({bytes_in}\d+)""",
    """filterlog:(?:[^,]*,){4}({dest_interface}[^,]*),({activity}[^,]*),({outcome}[^,]*),({direction}[^,]*),(?:[^,]*,){8}({protocol}icmp),[^,]*,({src_ip}[^,]*),({dest_ip}[^,]*),"""
  ]
}

{
  Name = s-atlassian-bitbucket-app-activity
  Vendor = Atlassian BitBucket
  Product = Atlassian BitBucket
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """ | SSH - git""" ]
  Fields = [
    """([^\|]*\|){4}\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """([^\|]*\|){0}\s*({src_ip}[A-Fa-f:\d.]+)\s*\|""",
    """([^\|]*\|){3}\s*({user}[^\s\|]+)""",
    """([^\|]*\|){5}\s*({action}[^\|]+?)\s*\|""",
    """([^\|]*\|){5}\s*SSH - ({activity}[^\|\']+)\s\'({object}[^\|\']+)\'""",
    """([^\|]*\|){10}\s*({additional_info}[^\|]+?)\s*\|""",
  ]
}
```