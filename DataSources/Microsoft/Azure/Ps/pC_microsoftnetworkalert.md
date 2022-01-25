#### Parser Content
```Java
{
Name = microsoft-network-alert
  Vendor = Microsoft
  Product = Azure
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName =Azure""", """"category":"FrontdoorWebApplicationFirewallLog"""",""""action":"Block""""]
  Fields = [
    """"time":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)"""",
    """"host":"({host}[^"]{1,2000})""",
    """"clientIP":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
    """"clientPort":"({src_port}\d{1,100})""""
    """"resourceId":"({object}[^"]{1,2000})"""
    """"resourceId":"\/([^\/]{0,2000}\/){7}({dest_host}[^"]{1,2000})""",
    """"ruleName":"({policy}[^"]{1,2000})""",
    """"ruleName":"({alert_name}[^"]{1,2000})""",
    """"category":"({alert_type}[^"]{1,2000})""",
    """"action":"({action}[^"]{1,2000})""""
    """suser=(anonymous|({user}[^=]{1,2000}?))\s{1,100}\w+=""",
    """"requestUri":"({full_url}.+?)","""",
    """Namespace:\s{0,100}({event_hub_namespace}\S+)""",
    """EventHub name:\s{0,100}({event_hub_name}[^\]\s]{1,2000})\s{0,100}\]""",
    """"msg":"({alert_name}[^"]{1,2000})""""
  ]
   DupFields = ["event_hub_namespace->host", "action->outcome"]


}
```