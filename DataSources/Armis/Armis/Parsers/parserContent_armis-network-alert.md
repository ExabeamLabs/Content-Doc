#### Parser Content
```Java
{
Name = armis-network-alert
  Vendor = Armis
  Product = Armis
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"relatedDevices":""", """"actionType":""" , """"hostname":""" ]
  Fields = [
    """_time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """content"\s*:\s*"({alert_name}.+?)",""",
    """title"\s*:\s*"({policy}[^"]+)""",
    """hostname.+?type"\s*:\s*"({alert_type}[^"]+)"""
    """actionType"\s*:\s*"({alert_severity}[^"]+)""",
    """hostname"\s*:\s*"({host}[^"]+)""",
    """rules.+?type\s*:({additional_info}.+?)"]}""",
    """relatedDevices.+?category"\s*:\s*"(HANDHELD|COMPUTER|UNKNOWN).+?name"\s*:\s*"({src_host}[^"]+)"""
    """user"\s*:\s*"({user}[^"]+)""",
    """inboundTraffic"\s*:\s*({bytes_in}[^",\s]+)""",
    """outboundTraffic"\s*:\s*({bytes_out}[^",\s]+)""",
    """protocol"\s*:\s*\["({app_protocol}[^",\s]+)""",
    """relatedLinks.+?id"\s*:\s*"({alert_id}[^",\s]+)""",
    """status"\s*:\s*"({outcome}[^\s"]+)"""
  ]
}
```