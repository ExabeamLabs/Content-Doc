#### Parser Content
```Java
{
Name = netskope-network-connection
    Vendor = Netskope
    Product = Netskope
    Lms = Direct
    DataType = "network-connection"
    TimeFormat = "epoch_sec"
    Conditions = [ """"bypass_traffic":""", """"traffic_type":""", """"userkey":""" ]
    Fields = [
      """"+bypass_reason"+:\s*"+({action}[^",]+)""",
      """"+url"+:\s*"+({domain}[^",]+)""",
      """"user"+:\s*"+(({user_email}[^@]+@[^",]+)|({user}[^",]+))""",
      """"+dstport"+:\s*({dest_port}\d+)""",
      """"hostname"+:\s*"+({host}[^",]+)""",
      """"+appcategory"+:\s*"+({category}[^",]+)""",
      """"timestamp"+:\s*({time}\d+)""",
      """"+src_location"+:\s*"+({location_city}[^",]+)""",
      """"+bypass_traffic"+:\s*"+({outcome}[^",]+)""",
      """"+userip"+:\s*"+({src_ip}[^",]+)""",
      """"+src_country"+:\s*"+({country_code}[^",]+)""",
      """"srcip":\s*"({src_translated_ip}[A-Fa-f:\d.]+)"""",
      """"+dstip"+:\s*"+({dest_ip}[^",]+)""",
      """"policy": "({alert_name}[^",]+)""",
      """"+browser"+:\s*"+({browser}[^",]+)""",
      """"+useragent"+:\s*"+({user_agent}[^"]+)""",
    ]
  }
```