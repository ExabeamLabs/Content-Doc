#### Parser Content
```Java
{
Name = azure-event-hub-application-gateway-firewall-log
  DataType = "app-activity"
  Conditions = ["""ext_category=ApplicationGatewayFirewallLog""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """\Wext_properties_hostname=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\Wext_properties_message=(|({src_ip}.+?))(\s+\w+=|\s*$)""",
    """\Wext_properties_action=(|({action}.+?))(\s+\w+=|\s*$)""",
    """\Wext_properties_transactionId=(|({transaction_id}.+?))(\s+\w+=|\s*$)""",
    """\Wext_properties_clientIp=({src_ip}[a-fA-F\d.:]+)""",
    """operationName":"({activity}.*?[^\\])"""",
    """requestUri":"({request_uri}.*?[^\\])"""",
    """message":"({additional_info}.*?[^\\])"""",
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```