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
    """"time":"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)"""",
    """"host":"({host}[^"]+)""",
    """"clientIP":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
    """"clientPort":"({src_port}\d+)""""
    """"resourceId":"({object}[^"]+)"""
    """"resourceId":"\/([^\/]*\/){7}({dest_host}[^"]+)""",
    """"ruleName":"({alert_name}[^"]+)""",
    """"category":"({alert_type}[^"]+)""",
    """"action":"({action}[^"]+)""""
    """suser=(anonymous|({user}.+?))\s+\w+=""",
    """"requestUri":"({full_url}[^"]+)""""
  ]
}
```