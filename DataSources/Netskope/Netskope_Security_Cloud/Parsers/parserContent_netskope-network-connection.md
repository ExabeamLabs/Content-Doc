#### Parser Content
```Java
{
Name = netskope-network-connection
    Vendor = Netskope
    Product = Netskope Security Cloud
    Lms = Direct
    DataType = "network-connection"
    TimeFormat = "epoch_sec"
    Conditions = [ """"bypass_traffic":""", """"traffic_type":""", """"userkey":""" ]
    Fields = [
      """"{1,20}bypass_reason"{1,20}:\s{0,100}"{1,20}({action}[^",]+)""",
      """"{1,20}url"{1,20}:\s{0,100}"{1,20}({domain}[^",]+)""",
      """"user"{1,20}:\s{0,100}"{1,20}(({user_email}[^@]+@[^",]+)|({user}[^",]+))""",
      """"{1,20}dstport"{1,20}:\s{0,100}({dest_port}\d{1,100})""",
      """"hostname"{1,20}:\s{0,100}"{1,20}({host}[^",]+)""",
      """"{1,20}appcategory"{1,20}:\s{0,100}"{1,20}({category}[^",]+)""",
      """"timestamp"{1,20}:\s{0,100}({time}\d{1,100})""",
      """"{1,20}src_location"{1,20}:\s{0,100}"{1,20}({location_city}[^",]+)""",
      """"{1,20}bypass_traffic"{1,20}:\s{0,100}"{1,20}({outcome}[^",]+)""",
      """"{1,20}userip"{1,20}:\s{0,100}"{1,20}({src_ip}[^",]+)""",
      """"{1,20}src_country"{1,20}:\s{0,100}"{1,20}({country_code}[^",]+)""",
      """"srcip":\s{0,100}"({src_translated_ip}[A-Fa-f:\d.]+)"""",
      """"{1,20}dstip"{1,20}:\s{0,100}"{1,20}({dest_ip}[^",]+)""",
      """"policy": "({alert_name}[^",]+)""",
      """"{1,20}browser"{1,20}:\s{0,100}"{1,20}({browser}[^",]+)""",
      """"{1,20}useragent"{1,20}:\s{0,100}"{1,20}({user_agent}[^"]+)""",
    ]
  }
```