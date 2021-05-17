#### Parser Content
```Java
{
Name = azure-event-hub-application-gateway-firewall-log
  DataType = "network-connection"
  Conditions = [""""category":"ApplicationGatewayFirewallLog"""","""CEF:""", """|SkyFormation Cloud Apps Security|""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """"clientIp":"({src_ip}[^"]{1,2000})""",
    """"clientPort":"({src_port}[^"]{1,2000})""",
    """"requestUri":"({request_uri}[^"]{1,2000})""",
    """"ruleSetType":"({rule}[^"]{1,2000})""",
    """"ruleId":"({rule_id}[^"]{1,2000})""",
    """"ruleGroup.+?"message":"({additional_info}[^"]{1,2000})""",
    """"action":"({outcome}[^"]{1,2000})""",
    """"transactionId":"({transaction_id}[^"]{1,2000})""",
    """"file":"({file_path}({file_parent}[^\/"]{1,2000})\/({file_name}[^"]{1,2000}))""",
    """originalHost":"(({src_ip}[A-Fa-f\d.:]{1,2000})|({src_host}.+?[^\\]))"""",
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```