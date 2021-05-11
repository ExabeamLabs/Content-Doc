#### Parser Content
```Java
{
Name = microsoft-network-alert
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Azure""", """"category":"FrontdoorWebApplicationFirewallLog"""",""""action":"Block""""]
  Fields = [
    """"time":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)"""",
    """"host":"({host}[^"]+)""",
    """"clientIP":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
    """"clientPort":"({src_port}\d{1,100})""""
    """"resourceId":"({object}[^"]+)"""
    """"resourceId":"\/([^\/]*\/){7}({dest_host}[^"]+)""",
    """"ruleName":"({policy}[^"]+)""",
    """"ruleName":"({alert_name}[^"]+)""",
    """"category":"({alert_type}[^"]+)""",
    """"action":"({action}[^"]+)""""
    """suser=(anonymous|({user}[^=]+?))\s{1,100}\w+=""",
    """"requestUri":"({full_url}.+?)","""",
    """Namespace:\s{0,100}({event_hub_namespace}\S+)""",
    """EventHub name:\s{0,100}({event_hub_name}[^\]\s]+)\s{0,100}\]""",
    """"msg":"({alert_name}[^"]+)""""
  ]
   DupFields = ["event_hub_namespace->host", "action->outcome"]
}
```