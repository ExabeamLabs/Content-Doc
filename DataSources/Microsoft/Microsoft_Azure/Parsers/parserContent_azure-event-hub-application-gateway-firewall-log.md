#### Parser Content
```Java
{
Name = azure-event-hub-application-gateway-firewall-log
  DataType = "network-connection"
  Conditions = [""""category":"ApplicationGatewayFirewallLog"""","""CEF:""", """|SkyFormation Cloud Apps Security|""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """"clientIp":"({src_ip}[^"]+)""",
    """"clientPort":"({src_port}[^"]+)""",
    """"requestUri":"({request_uri}[^"]+)""",
    """"ruleSetType":"({rule}[^"]+)""",
    """"ruleId":"({rule_id}[^"]+)""",
    """"ruleGroup.+?"message":"({additional_info}[^"]+)""",
    """"action":"({outcome}[^"]+)""",
    """"transactionId":"({transaction_id}[^"]+)""",
    """"file":"({file_path}({file_parent}[^\/"]+)\/({file_name}[^"]+))""",
    """originalHost":"(({src_ip}[A-Fa-f\d.:]+)|({src_host}.+?[^\\]))"""",
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```